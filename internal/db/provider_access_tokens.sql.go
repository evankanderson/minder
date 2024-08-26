// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: provider_access_tokens.sql

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
)

const getAccessTokenByEnrollmentNonce = `-- name: GetAccessTokenByEnrollmentNonce :one
SELECT id, provider, project_id, owner_filter, encrypted_token, expiration_time, created_at, updated_at, enrollment_nonce, encrypted_access_token FROM provider_access_tokens WHERE project_id = $1 AND enrollment_nonce = $2
`

type GetAccessTokenByEnrollmentNonceParams struct {
	ProjectID       uuid.UUID      `json:"project_id"`
	EnrollmentNonce sql.NullString `json:"enrollment_nonce"`
}

func (q *Queries) GetAccessTokenByEnrollmentNonce(ctx context.Context, arg GetAccessTokenByEnrollmentNonceParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, getAccessTokenByEnrollmentNonce, arg.ProjectID, arg.EnrollmentNonce)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.OwnerFilter,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.EncryptedAccessToken,
	)
	return i, err
}

const getAccessTokenByProjectID = `-- name: GetAccessTokenByProjectID :one
SELECT id, provider, project_id, owner_filter, encrypted_token, expiration_time, created_at, updated_at, enrollment_nonce, encrypted_access_token FROM provider_access_tokens WHERE provider = $1 AND project_id = $2
`

type GetAccessTokenByProjectIDParams struct {
	Provider  string    `json:"provider"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetAccessTokenByProjectID(ctx context.Context, arg GetAccessTokenByProjectIDParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, getAccessTokenByProjectID, arg.Provider, arg.ProjectID)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.OwnerFilter,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.EncryptedAccessToken,
	)
	return i, err
}

const getAccessTokenByProvider = `-- name: GetAccessTokenByProvider :many
SELECT id, provider, project_id, owner_filter, encrypted_token, expiration_time, created_at, updated_at, enrollment_nonce, encrypted_access_token FROM provider_access_tokens WHERE provider = $1
`

func (q *Queries) GetAccessTokenByProvider(ctx context.Context, provider string) ([]ProviderAccessToken, error) {
	rows, err := q.db.QueryContext(ctx, getAccessTokenByProvider, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ProviderAccessToken{}
	for rows.Next() {
		var i ProviderAccessToken
		if err := rows.Scan(
			&i.ID,
			&i.Provider,
			&i.ProjectID,
			&i.OwnerFilter,
			&i.EncryptedToken,
			&i.ExpirationTime,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.EnrollmentNonce,
			&i.EncryptedAccessToken,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAccessTokenSinceDate = `-- name: GetAccessTokenSinceDate :one
SELECT id, provider, project_id, owner_filter, encrypted_token, expiration_time, created_at, updated_at, enrollment_nonce, encrypted_access_token FROM provider_access_tokens WHERE provider = $1 AND project_id = $2 AND updated_at >= $3
`

type GetAccessTokenSinceDateParams struct {
	Provider  string    `json:"provider"`
	ProjectID uuid.UUID `json:"project_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (q *Queries) GetAccessTokenSinceDate(ctx context.Context, arg GetAccessTokenSinceDateParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, getAccessTokenSinceDate, arg.Provider, arg.ProjectID, arg.UpdatedAt)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.OwnerFilter,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.EncryptedAccessToken,
	)
	return i, err
}

const listTokensToMigrate = `-- name: ListTokensToMigrate :many
SELECT id, provider, project_id, owner_filter, encrypted_token, expiration_time, created_at, updated_at, enrollment_nonce, encrypted_access_token FROM provider_access_tokens WHERE
    encrypted_access_token IS NULL OR
    encrypted_access_token->>'Algorithm'  <> $1::TEXT OR
    encrypted_access_token->>'KeyVersion' <> $2::TEXT
LIMIT  $4::bigint
OFFSET $3::bigint
`

type ListTokensToMigrateParams struct {
	DefaultAlgorithm  string `json:"default_algorithm"`
	DefaultKeyVersion string `json:"default_key_version"`
	BatchOffset       int64  `json:"batch_offset"`
	BatchSize         int64  `json:"batch_size"`
}

// When doing a key/algorithm rotation, identify the secrets which need to be
// rotated. The criteria for rotation are:
//  1. The encrypted_access_token is NULL (this should be removed when we make
//     this column non-nullable).
//  2. The access token does not use the configured default algorithm.
//  3. The access token does not use the default key version.
//
// This query accepts the default key version/algorithm as arguments since
// that information is not known to the database.
func (q *Queries) ListTokensToMigrate(ctx context.Context, arg ListTokensToMigrateParams) ([]ProviderAccessToken, error) {
	rows, err := q.db.QueryContext(ctx, listTokensToMigrate,
		arg.DefaultAlgorithm,
		arg.DefaultKeyVersion,
		arg.BatchOffset,
		arg.BatchSize,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ProviderAccessToken{}
	for rows.Next() {
		var i ProviderAccessToken
		if err := rows.Scan(
			&i.ID,
			&i.Provider,
			&i.ProjectID,
			&i.OwnerFilter,
			&i.EncryptedToken,
			&i.ExpirationTime,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.EnrollmentNonce,
			&i.EncryptedAccessToken,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateEncryptedSecret = `-- name: UpdateEncryptedSecret :exec
UPDATE provider_access_tokens
SET encrypted_access_token = $2::JSONB
WHERE id = $1
`

type UpdateEncryptedSecretParams struct {
	ID     int32           `json:"id"`
	Secret json.RawMessage `json:"secret"`
}

func (q *Queries) UpdateEncryptedSecret(ctx context.Context, arg UpdateEncryptedSecretParams) error {
	_, err := q.db.ExecContext(ctx, updateEncryptedSecret, arg.ID, arg.Secret)
	return err
}

const upsertAccessToken = `-- name: UpsertAccessToken :one
INSERT INTO provider_access_tokens
(project_id, provider, expiration_time, owner_filter, enrollment_nonce, encrypted_access_token)
VALUES
    ($1, $2, $3, $4, $5, $6)
ON CONFLICT (project_id, provider)
    DO UPDATE SET
                  expiration_time = $3,
                  owner_filter = $4,
                  enrollment_nonce = $5,
                  updated_at = NOW(),
                  encrypted_access_token = $6
WHERE provider_access_tokens.project_id = $1 AND provider_access_tokens.provider = $2
RETURNING id, provider, project_id, owner_filter, encrypted_token, expiration_time, created_at, updated_at, enrollment_nonce, encrypted_access_token
`

type UpsertAccessTokenParams struct {
	ProjectID            uuid.UUID             `json:"project_id"`
	Provider             string                `json:"provider"`
	ExpirationTime       time.Time             `json:"expiration_time"`
	OwnerFilter          sql.NullString        `json:"owner_filter"`
	EnrollmentNonce      sql.NullString        `json:"enrollment_nonce"`
	EncryptedAccessToken pqtype.NullRawMessage `json:"encrypted_access_token"`
}

func (q *Queries) UpsertAccessToken(ctx context.Context, arg UpsertAccessTokenParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, upsertAccessToken,
		arg.ProjectID,
		arg.Provider,
		arg.ExpirationTime,
		arg.OwnerFilter,
		arg.EnrollmentNonce,
		arg.EncryptedAccessToken,
	)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.OwnerFilter,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.EncryptedAccessToken,
	)
	return i, err
}
