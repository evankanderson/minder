// SPDX-FileCopyrightText: Copyright 2023 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

// Package rest provides the REST rule data ingest engine
package rest

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-github/v63/github"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/mindersec/minder/internal/util"
	pb "github.com/mindersec/minder/pkg/api/protobuf/go/minder/v1"
	"github.com/mindersec/minder/pkg/engine/v1/interfaces"
	"github.com/mindersec/minder/pkg/entities/v1/checkpoints"
)

const (
	// RestRuleDataIngestType is the type of the REST rule data ingest engine
	RestRuleDataIngestType = "rest"

	// MaxBytesLimit is the maximum number of bytes to read from the response body
	// We limit to 1MB to prevent abuse
	MaxBytesLimit int64 = 1 << 20
	// endpointBytesLimit is the maximum number of bytes for the endpoint
	endpointBytesLimit = 1024
	// bodyBytesLimit is the maximum number of bytes for the body
	bodyBytesLimit = 1024
	// methodBytesLimit is the maximum number of bytes for the method
	methodBytesLimit = 10
)

type ingestorFallback struct {
	// httpCode is the HTTP status code to return
	httpCode int
	// Body is the body to return
	body string
}

// Ingestor is the engine for a rule type that uses REST data ingest
type Ingestor struct {
	restCfg          *pb.RestType
	cli              interfaces.RESTProvider
	endpointTemplate *util.SafeTemplate
	bodyTemplate     *util.SafeTemplate
	methodTemplate   *util.SafeTemplate
	fallback         []ingestorFallback
}

// NewRestRuleDataIngest creates a new REST rule data ingest engine
func NewRestRuleDataIngest(
	restCfg *pb.RestType,
	cli interfaces.RESTProvider,
) (*Ingestor, error) {
	if len(restCfg.Endpoint) == 0 {
		return nil, fmt.Errorf("missing endpoint")
	}

	tmpl, err := util.NewSafeTextTemplate(&restCfg.Endpoint, "endpoint")
	if err != nil {
		return nil, fmt.Errorf("cannot parse endpoint template: %w", err)
	}

	var bodyTmpl *util.SafeTemplate
	if restCfg.GetBody() != "" {
		bodyTmpl, err = util.NewSafeHTMLTemplate(restCfg.Body, "body")
		if err != nil {
			return nil, fmt.Errorf("cannot parse body template: %w", err)
		}
	}

	method := cmp.Or(restCfg.Method, http.MethodGet)
	methodTmpl, err := util.NewSafeTextTemplate(&method, "method")
	if err != nil {
		return nil, fmt.Errorf("cannot parse method template: %w", err)
	}

	fallback := make([]ingestorFallback, len(restCfg.Fallback))
	for _, fb := range restCfg.Fallback {
		fb := fb
		fallback = append(fallback, ingestorFallback{
			httpCode: int(fb.HttpCode),
			body:     fb.Body,
		})
	}

	return &Ingestor{
		restCfg:          restCfg,
		cli:              cli,
		endpointTemplate: tmpl,
		bodyTemplate:     bodyTmpl,
		methodTemplate:   methodTmpl,
		fallback:         fallback,
	}, nil
}

// EndpointTemplateParams is the parameters for the REST endpoint template
type EndpointTemplateParams struct {
	// Entity is the entity to be evaluated
	Entity any
	// Params are the parameters to be used in the template
	Params map[string]any
}

// GetType returns the type of the REST rule data ingest engine
func (*Ingestor) GetType() string {
	return RestRuleDataIngestType
}

// GetConfig returns the config for the REST rule data ingest engine
func (rdi *Ingestor) GetConfig() protoreflect.ProtoMessage {
	return rdi.restCfg
}

// Ingest calls the REST endpoint and returns the data
func (rdi *Ingestor) Ingest(
	ctx context.Context, ent protoreflect.ProtoMessage, params map[string]any,
) (*interfaces.Ingested, error) {
	retp := &EndpointTemplateParams{
		Entity: ent,
		Params: params,
	}

	endpoint, err := rdi.endpointTemplate.Render(ctx, retp, endpointBytesLimit)
	if err != nil {
		return nil, fmt.Errorf("cannot execute endpoint template: %w", err)
	}

	var bodyOut any
	if rdi.bodyTemplate != nil {
		var body bytes.Buffer
		if err := rdi.bodyTemplate.Execute(ctx, &body, retp, bodyBytesLimit); err != nil {
			return nil, fmt.Errorf("cannot execute body template: %w", err)
		}
		// Newlines are not valid in JSON, but are handy when writing e.g. graphql queries.
		data := bytes.ReplaceAll(body.Bytes(), []byte("\n"), []byte(" "))
		if err := json.Unmarshal(data, &bodyOut); err != nil {
			return nil, fmt.Errorf("cannot parse request body as JSON: %w", err)
		}
	}

	method, err := rdi.methodTemplate.Render(ctx, retp, methodBytesLimit)
	if err != nil {
		return nil, fmt.Errorf("cannot execute method template: %w", err)
	}
	method = strings.ToUpper(method)

	req, err := rdi.cli.NewRequest(method, endpoint, bodyOut)
	if err != nil {
		return nil, fmt.Errorf("cannot create request: %w", err)
	}

	respRdr, err := rdi.doRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("cannot do request: %w", err)
	}

	defer func() {
		if err := respRdr.Close(); err != nil {
			log.Printf("cannot close response body: %v", err)
		}
	}()

	data, err := rdi.parseBody(respRdr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse body: %w", err)
	}

	return &interfaces.Ingested{
		Object:     data,
		Checkpoint: checkpoints.NewCheckpointV1Now().WithHTTP(endpoint, method),
	}, nil
}

func (rdi *Ingestor) doRequest(ctx context.Context, req *http.Request) (io.ReadCloser, error) {
	resp, err := rdi.cli.Do(ctx, req)
	if err == nil {
		// Early-exit on success
		return resp.Body, nil
	}

	if fallbackBody := errorToFallback(err, rdi.fallback); fallbackBody != nil {
		// the go-github REST API has a funny way of returning HTTP status codes,
		// on a non-200 status it will return a github.ErrorResponse
		// whereas the standard library will return nil error and the HTTP status code in the response
		return fallbackBody, nil
	}

	return nil, fmt.Errorf("cannot make request: %w", err)
}

func errorToFallback(err error, fallback []ingestorFallback) io.ReadCloser {
	var respErr *github.ErrorResponse
	if errors.As(err, &respErr) {
		if respErr.Response != nil {
			return httpStatusToFallback(respErr.Response.StatusCode, fallback)
		}
	}

	return nil
}

func httpStatusToFallback(httpStatus int, fallback []ingestorFallback) io.ReadCloser {
	for _, fb := range fallback {
		if fb.httpCode == httpStatus {
			zerolog.Ctx(context.Background()).Debug().Msgf("falling back to body [%s]", fb.body)
			return io.NopCloser(strings.NewReader(fb.body))
		}
	}

	return nil
}

func (rdi *Ingestor) parseBody(body io.Reader) (any, error) {
	var data any
	var err error

	if body == nil {
		return nil, nil
	}

	lr := io.LimitReader(body, MaxBytesLimit)

	if rdi.restCfg.Parse == "json" {
		var jsonData any
		dec := json.NewDecoder(lr)
		if err := dec.Decode(&jsonData); err != nil {
			return nil, fmt.Errorf("cannot decode json: %w", err)
		}

		data = jsonData
	} else {
		data, err = io.ReadAll(lr)
		if err != nil {
			return nil, fmt.Errorf("cannot read response body: %w", err)
		}
	}

	return data, nil
}
