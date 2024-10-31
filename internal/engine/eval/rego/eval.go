// SPDX-FileCopyrightText: Copyright 2023 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

// Package rego provides the rego rule evaluator
package rego

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"google.golang.org/protobuf/reflect/protoreflect"

	eoptions "github.com/mindersec/minder/internal/engine/options"
	minderv1 "github.com/mindersec/minder/pkg/api/protobuf/go/minder/v1"
	"github.com/mindersec/minder/pkg/engine/v1/interfaces"
)

const (
	// RegoEvalType is the type of the rego evaluator
	RegoEvalType = "rego"
	// MinderRegoFile is the default rego file for minder.
	MinderRegoFile = "minder.rego"
	// RegoQueryPrefix is the prefix for rego queries
	RegoQueryPrefix = "data.minder"
)

const (
	// EnablePrintEnvVar is the environment variable to enable print statements
	EnablePrintEnvVar = "REGO_ENABLE_PRINT"
)

func publicDialer(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			fmt.Printf("Got error: %v\n", err)
			return nil, err
		}
		fmt.Printf("Got Conn to %+v (%T)\n", conn.RemoteAddr(), conn.RemoteAddr())
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("could not get remote address")
		}
		if remote == nil {
			return nil, fmt.Errorf("remote address is nil")
		}
		if !remote.IP.IsGlobalUnicast() || remote.IP.IsLoopback() || remote.IP.IsPrivate() {
			fmt.Printf("BLOCKED!!!!\n")
			return nil, fmt.Errorf("remote address is not a public IP")
		}
		return conn, err
	}
}

func init() {
	publicNetTransport := &http.Transport{
		DialContext: publicDialer(&net.Dialer{}),
	}
	http.DefaultTransport = publicNetTransport
}

// Evaluator is the evaluator for rego rules
// It initializes the rego engine and evaluates the rules
// The default rego package is "minder"
type Evaluator struct {
	cfg      *Config
	regoOpts []func(*rego.Rego)
	reseval  resultEvaluator
}

// Input is the input for the rego evaluator
type Input struct {
	// Profile is the values set for the profile
	Profile map[string]any `json:"profile"`
	// Ingested is the values set for the ingested data
	Ingested any `json:"ingested"`
	// OutputFormat is the format to output violations in
	OutputFormat ConstraintsViolationsFormat `json:"output_format"`
}

// NewRegoEvaluator creates a new rego evaluator
func NewRegoEvaluator(
	cfg *minderv1.RuleType_Definition_Eval_Rego,
	opts ...eoptions.Option,
) (*Evaluator, error) {
	c, err := parseConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not parse rego config: %w", err)
	}

	re := c.getEvalType()

	eval := &Evaluator{
		cfg:     c,
		reseval: re,
		regoOpts: []func(*rego.Rego){
			re.getQuery(),
			rego.Module(MinderRegoFile, c.Def),
			rego.Strict(true),
			// rego.UnsafeBuiltins(map[string]struct{}{"http.send": {}}),
		},
	}

	for _, opt := range opts {
		if err := opt(eval); err != nil {
			return nil, err
		}
	}

	if os.Getenv(EnablePrintEnvVar) == "true" {
		eval.regoOpts = append(eval.regoOpts,
			rego.EnablePrintStatements(true),
			rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		)
	}

	return eval, nil
}

func (e *Evaluator) newRegoFromOptions(opts ...func(*rego.Rego)) *rego.Rego {
	return rego.New(append(e.regoOpts, opts...)...)
}

// Eval implements the Evaluator interface.
func (e *Evaluator) Eval(
	ctx context.Context, pol map[string]any, entity protoreflect.ProtoMessage, res *interfaces.Result,
) error {
	// The rego engine is actually able to handle nil
	// objects quite gracefully, so we don't need to check
	// this explicitly.
	obj := res.Object

	libFuncs := instantiateRegoLib(res)
	r := e.newRegoFromOptions(
		libFuncs...,
	)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("could not prepare Rego: %w", err)
	}

	rs, err := pq.Eval(ctx, rego.EvalInput(&Input{
		Profile:      pol,
		Ingested:     obj,
		OutputFormat: e.cfg.ViolationFormat,
	}))
	if err != nil {
		return fmt.Errorf("error evaluating profile. Might be wrong input: %w", err)
	}

	return e.reseval.parseResult(rs, entity)
}
