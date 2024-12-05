// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: subscriptions.sql

package db

import (
	"context"

	"github.com/google/uuid"
)

const createSubscription = `-- name: CreateSubscription :one

INSERT INTO subscriptions (project_id, bundle_id, current_version)
VALUES ($1, $2, $3)
RETURNING id, project_id, bundle_id, current_version
`

type CreateSubscriptionParams struct {
	ProjectID      uuid.UUID `json:"project_id"`
	BundleID       uuid.UUID `json:"bundle_id"`
	CurrentVersion string    `json:"current_version"`
}

// Subscriptions --
func (q *Queries) CreateSubscription(ctx context.Context, arg CreateSubscriptionParams) (Subscription, error) {
	row := q.db.QueryRowContext(ctx, createSubscription, arg.ProjectID, arg.BundleID, arg.CurrentVersion)
	var i Subscription
	err := row.Scan(
		&i.ID,
		&i.ProjectID,
		&i.BundleID,
		&i.CurrentVersion,
	)
	return i, err
}

const getBundle = `-- name: GetBundle :one
SELECT id, namespace, name FROM bundles WHERE namespace = $1 AND name = $2
`

type GetBundleParams struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func (q *Queries) GetBundle(ctx context.Context, arg GetBundleParams) (Bundle, error) {
	row := q.db.QueryRowContext(ctx, getBundle, arg.Namespace, arg.Name)
	var i Bundle
	err := row.Scan(&i.ID, &i.Namespace, &i.Name)
	return i, err
}

const getSubscriptionByProjectBundle = `-- name: GetSubscriptionByProjectBundle :one
SELECT su.id, su.project_id, su.bundle_id, su.current_version FROM subscriptions AS su
JOIN bundles AS bu ON bu.id = su.bundle_id
WHERE bu.namespace = $1 AND bu.name = $2 AND su.project_id = $3
`

type GetSubscriptionByProjectBundleParams struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetSubscriptionByProjectBundle(ctx context.Context, arg GetSubscriptionByProjectBundleParams) (Subscription, error) {
	row := q.db.QueryRowContext(ctx, getSubscriptionByProjectBundle, arg.Namespace, arg.Name, arg.ProjectID)
	var i Subscription
	err := row.Scan(
		&i.ID,
		&i.ProjectID,
		&i.BundleID,
		&i.CurrentVersion,
	)
	return i, err
}

const setSubscriptionBundleVersion = `-- name: SetSubscriptionBundleVersion :exec
UPDATE subscriptions SET current_version = $2 WHERE project_id = $1
`

type SetSubscriptionBundleVersionParams struct {
	ProjectID      uuid.UUID `json:"project_id"`
	CurrentVersion string    `json:"current_version"`
}

func (q *Queries) SetSubscriptionBundleVersion(ctx context.Context, arg SetSubscriptionBundleVersionParams) error {
	_, err := q.db.ExecContext(ctx, setSubscriptionBundleVersion, arg.ProjectID, arg.CurrentVersion)
	return err
}

const upsertBundle = `-- name: UpsertBundle :exec


INSERT INTO bundles (namespace, name) VALUES ($1, $2)
ON CONFLICT DO NOTHING
`

type UpsertBundleParams struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// SPDX-FileCopyrightText: Copyright 2024 The Minder Authors
// SPDX-License-Identifier: Apache-2.0
// Bundles --
func (q *Queries) UpsertBundle(ctx context.Context, arg UpsertBundleParams) error {
	_, err := q.db.ExecContext(ctx, upsertBundle, arg.Namespace, arg.Name)
	return err
}
