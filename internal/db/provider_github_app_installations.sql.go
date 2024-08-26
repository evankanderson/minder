// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: provider_github_app_installations.sql

package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const deleteInstallationIDByAppID = `-- name: DeleteInstallationIDByAppID :exec
DELETE FROM provider_github_app_installations WHERE app_installation_id = $1
`

func (q *Queries) DeleteInstallationIDByAppID(ctx context.Context, appInstallationID int64) error {
	_, err := q.db.ExecContext(ctx, deleteInstallationIDByAppID, appInstallationID)
	return err
}

const getInstallationIDByAppID = `-- name: GetInstallationIDByAppID :one
SELECT app_installation_id, provider_id, organization_id, enrolling_user_id, created_at, updated_at, enrollment_nonce, project_id, is_org FROM provider_github_app_installations WHERE app_installation_id = $1
`

func (q *Queries) GetInstallationIDByAppID(ctx context.Context, appInstallationID int64) (ProviderGithubAppInstallation, error) {
	row := q.db.QueryRowContext(ctx, getInstallationIDByAppID, appInstallationID)
	var i ProviderGithubAppInstallation
	err := row.Scan(
		&i.AppInstallationID,
		&i.ProviderID,
		&i.OrganizationID,
		&i.EnrollingUserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.ProjectID,
		&i.IsOrg,
	)
	return i, err
}

const getInstallationIDByEnrollmentNonce = `-- name: GetInstallationIDByEnrollmentNonce :one
SELECT app_installation_id, provider_id, organization_id, enrolling_user_id, created_at, updated_at, enrollment_nonce, project_id, is_org FROM provider_github_app_installations WHERE project_id = $1 AND enrollment_nonce = $2
`

type GetInstallationIDByEnrollmentNonceParams struct {
	ProjectID       uuid.NullUUID  `json:"project_id"`
	EnrollmentNonce sql.NullString `json:"enrollment_nonce"`
}

func (q *Queries) GetInstallationIDByEnrollmentNonce(ctx context.Context, arg GetInstallationIDByEnrollmentNonceParams) (ProviderGithubAppInstallation, error) {
	row := q.db.QueryRowContext(ctx, getInstallationIDByEnrollmentNonce, arg.ProjectID, arg.EnrollmentNonce)
	var i ProviderGithubAppInstallation
	err := row.Scan(
		&i.AppInstallationID,
		&i.ProviderID,
		&i.OrganizationID,
		&i.EnrollingUserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.ProjectID,
		&i.IsOrg,
	)
	return i, err
}

const getInstallationIDByProviderID = `-- name: GetInstallationIDByProviderID :one
SELECT app_installation_id, provider_id, organization_id, enrolling_user_id, created_at, updated_at, enrollment_nonce, project_id, is_org FROM provider_github_app_installations WHERE provider_id = $1
`

func (q *Queries) GetInstallationIDByProviderID(ctx context.Context, providerID uuid.NullUUID) (ProviderGithubAppInstallation, error) {
	row := q.db.QueryRowContext(ctx, getInstallationIDByProviderID, providerID)
	var i ProviderGithubAppInstallation
	err := row.Scan(
		&i.AppInstallationID,
		&i.ProviderID,
		&i.OrganizationID,
		&i.EnrollingUserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.ProjectID,
		&i.IsOrg,
	)
	return i, err
}

const getUnclaimedInstallationsByUser = `-- name: GetUnclaimedInstallationsByUser :many
SELECT app_installation_id, provider_id, organization_id, enrolling_user_id, created_at, updated_at, enrollment_nonce, project_id, is_org FROM provider_github_app_installations WHERE enrolling_user_id = $1 AND provider_id IS NULL
`

func (q *Queries) GetUnclaimedInstallationsByUser(ctx context.Context, ghID sql.NullString) ([]ProviderGithubAppInstallation, error) {
	rows, err := q.db.QueryContext(ctx, getUnclaimedInstallationsByUser, ghID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ProviderGithubAppInstallation{}
	for rows.Next() {
		var i ProviderGithubAppInstallation
		if err := rows.Scan(
			&i.AppInstallationID,
			&i.ProviderID,
			&i.OrganizationID,
			&i.EnrollingUserID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.EnrollmentNonce,
			&i.ProjectID,
			&i.IsOrg,
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

const upsertInstallationID = `-- name: UpsertInstallationID :one
INSERT INTO provider_github_app_installations
    (organization_id, app_installation_id, provider_id, enrolling_user_id, enrollment_nonce, project_id, is_org)
VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (organization_id)
    DO
UPDATE SET
    app_installation_id = $2,
    provider_id = $3,
    enrolling_user_id = $4,
    enrollment_nonce = $5,
    project_id = $6,
    is_org = $7,
    updated_at = NOW()
WHERE provider_github_app_installations.organization_id = $1
    RETURNING app_installation_id, provider_id, organization_id, enrolling_user_id, created_at, updated_at, enrollment_nonce, project_id, is_org
`

type UpsertInstallationIDParams struct {
	OrganizationID    int64          `json:"organization_id"`
	AppInstallationID int64          `json:"app_installation_id"`
	ProviderID        uuid.NullUUID  `json:"provider_id"`
	EnrollingUserID   sql.NullString `json:"enrolling_user_id"`
	EnrollmentNonce   sql.NullString `json:"enrollment_nonce"`
	ProjectID         uuid.NullUUID  `json:"project_id"`
	IsOrg             bool           `json:"is_org"`
}

func (q *Queries) UpsertInstallationID(ctx context.Context, arg UpsertInstallationIDParams) (ProviderGithubAppInstallation, error) {
	row := q.db.QueryRowContext(ctx, upsertInstallationID,
		arg.OrganizationID,
		arg.AppInstallationID,
		arg.ProviderID,
		arg.EnrollingUserID,
		arg.EnrollmentNonce,
		arg.ProjectID,
		arg.IsOrg,
	)
	var i ProviderGithubAppInstallation
	err := row.Scan(
		&i.AppInstallationID,
		&i.ProviderID,
		&i.OrganizationID,
		&i.EnrollingUserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.EnrollmentNonce,
		&i.ProjectID,
		&i.IsOrg,
	)
	return i, err
}
