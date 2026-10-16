// SPDX-FileCopyrightText: Copyright 2026 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/mindersec/minder/internal/db"
	entityService "github.com/mindersec/minder/internal/entities/service"
	entitySvc "github.com/mindersec/minder/internal/entities/service"
	"github.com/mindersec/minder/internal/providers/github"
	"github.com/mindersec/minder/internal/providers/manager"
	minderv1 "github.com/mindersec/minder/pkg/api/protobuf/go/minder/v1"
	"github.com/mindersec/minder/pkg/entities/properties"
)

// BackfillOrganizations loops through GitHub app providers and ensures an organization entity is tracked for each
func BackfillOrganizations(ctx context.Context, store db.Store, mgr manager.ProviderManager, creator entityService.EntityCreator) error {
	l := zerolog.Ctx(ctx)
	l.Info().Msg("Starting backfill for Organization entities...")

	provs, err := store.GlobalListProvidersByClass(ctx, db.ProviderClassGithubApp)
	if err != nil {
		return fmt.Errorf("failed to list providers: %w", err)
	}

	count := 0

	for _, dbProv := range provs {
		login := github.GetGithubAppOwner(dbProv.Name)

		_, err = db.WithTransaction(store, func(qtx db.ExtendQuerier) (any, error) {
			// Check if organization entity already exists
			_, err := qtx.GetEntityByName(ctx, db.GetEntityByNameParams{
				EntityType: db.EntitiesOrganization,
				Name:       login,
				ProviderID: dbProv.ID,
				ProjectID:  dbProv.ProjectID,
			})

			if err == nil {
				return nil, nil // already exists
			} else if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}

			fetchByProps := properties.NewProperties(map[string]any{
				properties.PropertyName: login,
			})

			if _, err := creator.CreateEntity(ctx, qtx, &dbProv, dbProv.ProjectID,
				minderv1.Entity_ENTITY_ORGANIZATION, fetchByProps, &entitySvc.EntityCreationOptions{
					RegisterWithProvider:       false, // Create webhook
					PublishReconciliationEvent: true,
				}); err != nil {
				zerolog.Ctx(ctx).Error().Err(err).Str("provider", dbProv.ID.String()).Msg("Failed to create organization entity")
			}

			return nil, err
		})

		if err != nil {
			l.Error().Err(err).Str("provider", dbProv.ID.String()).Msg("Failed to backfill organization for provider")
		}
	}

	l.Info().Int("count", count).Msg("Completed backfill for Organization entities")
	return nil
}
