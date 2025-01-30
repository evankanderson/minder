// SPDX-FileCopyrightText: Copyright 2023 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// MinderAuthTokenEnvVar is the environment variable for the minder auth token
//
//nolint:gosec // This is not a hardcoded credential
const MinderAuthTokenEnvVar = "MINDER_AUTH_TOKEN"

// ErrGettingRefreshToken is an error for when we can't get a refresh token
var ErrGettingRefreshToken = errors.New("error refreshing credentials")

// OpenIdCredentials is a struct to hold the access and refresh tokens
type OpenIdCredentials struct {
	AccessToken          string    `json:"access_token"`
	RefreshToken         string    `json:"refresh_token"`
	AccessTokenExpiresAt time.Time `json:"expiry"`
}

func getCredentialsPath() (string, error) {
	cfgPath, err := GetConfigDirPath()
	if err != nil {
		return "", fmt.Errorf("error getting config path: %v", err)
	}

	filePath := filepath.Join(cfgPath, "credentials.json")
	return filePath, nil
}

// JWTTokenCredentials is a helper struct for grpc
type JWTTokenCredentials struct {
	accessToken string
}

// GetRequestMetadata implements the PerRPCCredentials interface.
func (jwt JWTTokenCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + string(jwt.accessToken),
	}, nil
}

// RequireTransportSecurity implements the PerRPCCredentials interface.
func (JWTTokenCredentials) RequireTransportSecurity() bool {
	return false
}

// GetGrpcConnection is a helper for getting a testing connection for grpc
func GetGrpcConnection(
	grpc_host string, grpc_port int,
	allowInsecure bool,
	issuerUrl string, clientId string,
	opts ...grpc.DialOption) (
	*grpc.ClientConn, error) {
	address := fmt.Sprintf("%s:%d", grpc_host, grpc_port)

	// read credentials
	token := ""
	if os.Getenv(MinderAuthTokenEnvVar) != "" {
		token = os.Getenv(MinderAuthTokenEnvVar)
	} else {
		t, err := GetToken(issuerUrl, clientId)
		if err == nil {
			token = t
		}
	}

	credentialOpts := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: grpc_host,
	})
	if allowInsecure {
		credentialOpts = insecure.NewCredentials()
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentialOpts),
		grpc.WithPerRPCCredentials(JWTTokenCredentials{accessToken: token}),
	}
	dialOpts = append(dialOpts, opts...)

	// generate credentials
	conn, err := grpc.NewClient(address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("error connecting to gRPC server: %v", err)
	}

	return conn, nil
}

// SaveCredentials saves the credentials to a file
func SaveCredentials(tokens OpenIdCredentials) (string, error) {
	// marshal the credentials to json
	credsJSON, err := json.Marshal(tokens)
	if err != nil {
		return "", fmt.Errorf("error marshaling credentials: %v", err)
	}

	filePath, err := getCredentialsPath()
	if err != nil {
		return "", fmt.Errorf("error getting credentials path: %v", err)
	}

	err = os.MkdirAll(filepath.Dir(filePath), 0750)
	if err != nil {
		return "", fmt.Errorf("error creating directory: %v", err)
	}

	// Write the JSON data to the file
	err = os.WriteFile(filePath, credsJSON, 0600)
	if err != nil {
		return "", fmt.Errorf("error writing credentials to file: %v", err)
	}
	return filePath, nil
}

// RemoveCredentials removes the local credentials file
func RemoveCredentials() error {
	// remove credentials file
	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")

	// just delete token from credentials file
	if xdgConfigHome == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("error getting home directory: %v", err)
		}
		xdgConfigHome = filepath.Join(homeDir, ".config")
	}

	filePath := filepath.Join(xdgConfigHome, "minder", "credentials.json")
	err := os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("error removing credentials file: %v", err)
	}
	return nil
}

// GetToken retrieves the access token from the credentials file and refreshes it if necessary
func GetToken(issuerUrl string, clientId string) (string, error) {
	refreshLimit := 10
	creds, err := LoadCredentials()
	if err != nil {
		return "", fmt.Errorf("error loading credentials: %v", err)
	}
	needsRefresh := time.Now().Add(time.Duration(refreshLimit) * time.Second).After(creds.AccessTokenExpiresAt)

	if needsRefresh {
		updatedCreds, err := RefreshCredentials(creds.RefreshToken, issuerUrl, clientId)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrGettingRefreshToken, err)
		}
		return updatedCreds.AccessToken, nil
	}

	return creds.AccessToken, nil
}

type refreshTokenResponse struct {
	AccessToken          string `json:"access_token"`
	RefreshToken         string `json:"refresh_token"`
	AccessTokenExpiresIn int    `json:"expires_in"`
	// These will be present if there's an error
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// RefreshCredentials uses a refresh token to get and save a new set of credentials
func RefreshCredentials(refreshToken string, issuerUrl string, clientId string) (OpenIdCredentials, error) {

	parsedURL, err := url.Parse(issuerUrl)
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error parsing issuer URL: %v", err)
	}
	tokenUrl := parsedURL.JoinPath("realms/stacklok/protocol/openid-connect/token")

	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", tokenUrl.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error creating: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error fetching new credentials: %v", err)
	}
	defer resp.Body.Close()

	tokens := refreshTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(&tokens)
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error unmarshaling credentials: %v", err)
	}

	if tokens.Error != "" {
		return OpenIdCredentials{}, fmt.Errorf("error refreshing credentials: %s: %s", tokens.Error, tokens.ErrorDescription)
	}

	updatedCredentials := OpenIdCredentials{
		AccessToken:          tokens.AccessToken,
		RefreshToken:         tokens.RefreshToken,
		AccessTokenExpiresAt: time.Now().Add(time.Duration(tokens.AccessTokenExpiresIn) * time.Second),
	}
	_, err = SaveCredentials(updatedCredentials)
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error saving credentials: %v", err)
	}

	return updatedCredentials, nil
}

// LoadCredentials loads the credentials from a file
func LoadCredentials() (OpenIdCredentials, error) {
	filePath, err := getCredentialsPath()
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error getting credentials path: %v", err)
	}

	// Read the file
	credsJSON, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error reading credentials file: %v", err)
	}

	var creds OpenIdCredentials
	err = json.Unmarshal(credsJSON, &creds)
	if err != nil {
		return OpenIdCredentials{}, fmt.Errorf("error unmarshaling credentials: %v", err)
	}
	return creds, nil
}

// RevokeOfflineToken revokes the given offline token using OAuth2.0's Token Revocation endpoint
// from RFC 7009.
func RevokeOfflineToken(token string, issuerUrl string, clientId string) error {
	return RevokeToken(token, issuerUrl, clientId, "refresh_token")
}

// RevokeToken revokes the given token using OAuth2.0's Token Revocation endpoint
// from RFC 7009. The tokenHint is the type of token being revoked, such as
// "access_token" or "refresh_token". In the case of an offline token, the
// tokenHint should be "refresh_token".
func RevokeToken(token string, issuerUrl string, clientId string, tokenHint string) error {
	parsedURL, err := url.Parse(issuerUrl)
	if err != nil {
		return fmt.Errorf("error parsing issuer URL: %v", err)
	}
	logoutUrl := parsedURL.JoinPath("realms/stacklok/protocol/openid-connect/revoke")

	data := url.Values{}
	data.Set("client_id", clientId)
	data.Set("token", token)
	data.Set("token_type_hint", tokenHint)

	req, err := http.NewRequest("POST", logoutUrl.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("error creating: %v", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error revoking token: %v", err)
	}
	defer resp.Body.Close()

	return nil
}
