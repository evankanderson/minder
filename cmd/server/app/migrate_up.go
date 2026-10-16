// SPDX-FileCopyrightText: Copyright 2023 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

// Package app provides the entrypoint for the minder migrations
package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // nolint
	_ "github.com/golang-migrate/migrate/v4/source/file"       // nolint
	"github.com/open-feature/go-sdk/openfeature"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/mindersec/minder/database"
	"github.com/mindersec/minder/internal/authz"
	"github.com/mindersec/minder/internal/controlplane/metrics"
	"github.com/mindersec/minder/internal/crypto"
	"github.com/mindersec/minder/internal/db"
	properties "github.com/mindersec/minder/internal/entities/properties/service"
	entityService "github.com/mindersec/minder/internal/entities/service"
	"github.com/mindersec/minder/internal/entities/service/validators"
	"github.com/mindersec/minder/internal/providers"
	ghprov "github.com/mindersec/minder/internal/providers/github"
	"github.com/mindersec/minder/internal/providers/github/clients"
	ghmanager "github.com/mindersec/minder/internal/providers/github/manager"
	"github.com/mindersec/minder/internal/providers/github/service"
	"github.com/mindersec/minder/internal/providers/manager"
	"github.com/mindersec/minder/internal/providers/ratecache"
	"github.com/mindersec/minder/internal/providers/telemetry"
	"github.com/mindersec/minder/pkg/config"
	serverconfig "github.com/mindersec/minder/pkg/config/server"
	"github.com/mindersec/minder/pkg/eventer"
	"github.com/mindersec/minder/pkg/flags"
)

// upCmd represents the up command
var upCmd = &cobra.Command{
	Use:   "up",
	Short: "migrate the database to the latest version",
	Long:  `Command to upgrade database`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.ReadConfigFromViper[serverconfig.Config](viper.GetViper())
		if err != nil {
			return fmt.Errorf("unable to read config: %w", err)
		}

		ctx := serverconfig.LoggerFromConfigFlags(cfg.LoggingConfig).WithContext(context.Background())

		// Database configuration
		dbConn, connString, err := cfg.Database.GetDBConnection(ctx)
		if err != nil {
			return fmt.Errorf("unable to connect to database: %w", err)
		}
		defer dbConn.Close()

		yes := confirm(cmd, "Running this command will change the database structure")
		if !yes {
			return nil
		}

		m, err := database.NewFromConnectionString(connString)
		if err != nil {
			cliErrorf(cmd, "Error while creating migration instance: %v\n", err)
		}

		var usteps uint
		usteps, err = cmd.Flags().GetUint("num-steps")
		if err != nil {
			cmd.Printf("Error while getting num-steps flag: %v", err)
		}

		if usteps == 0 {
			err = m.Up()
		} else {
			err = m.Steps(int(usteps))
		}

		if err != nil {
			if !errors.Is(err, migrate.ErrNoChange) {
				cliErrorf(cmd, "Error while migrating database: %v\n", err)
			} else {
				cmd.Println("Database already up-to-date")
			}
		}

		cmd.Println("Database migration completed successfully")

		version, dirty, err := m.Version()
		if err != nil {
			cmd.Printf("Error while getting migration version: %v\n", err)
			// not fatal
		} else {
			cmd.Printf("Version=%v dirty=%v\n", version, dirty)
		}

		cmd.Println("Ensuring authorization store...")
		l := zerolog.Ctx(ctx)

		authzw, err := authz.NewAuthzClient(&cfg.Authz, l)
		if err != nil {
			return fmt.Errorf("error while creating authz client: %w", err)
		}

		if err := authzw.MigrateUp(ctx); err != nil {
			return fmt.Errorf("error while running authz migrations: %w", err)
		}

		if err := authzw.PrepareForRun(ctx); err != nil {
			return fmt.Errorf("error preparing authz client: %w", err)
		}

		cmd.Println("Backfilling organizations...")
		// create an EntityCreator from configuration, like in AllInOneServerService
		store := db.NewStore(dbConn)
		flags.OpenFeatureProviderFromFlags(ctx, cfg.Flags)
		featureFlagClient := openfeature.NewClient(cfg.Flags.AppName)

		propSvc := properties.NewPropertiesService(store)

		providerManager, closer, err := manager.NewProviderManager(ctx, providers.NewProviderStore(store))
		if err != nil {
			return fmt.Errorf("error while creating provider manager: %w", err)
		}
		defer closer()

		eventer, err := eventer.New(ctx, featureFlagClient, &cfg.Events)
		if err != nil {
			return fmt.Errorf("unable to setup eventer: %w", err)
		}
		validatorRegistry := validators.NewValidatorRegistry()

		entityCreator := entityService.NewEntityCreator(store, propSvc, providerManager, eventer, validatorRegistry)

		cryptoEngine, err := crypto.NewEngineFromConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to create crypto engine: %w", err)
		}
		ghClientFactory := clients.NewGitHubClientFactory(telemetry.NewNoopMetrics())
		migrateMetrics := metrics.NewMetrics()

		ghProviders := service.NewGithubProviderService(
			store,
			cryptoEngine,
			migrateMetrics,
			&cfg.Provider,
			func(_ context.Context, _ db.ExtendQuerier, _ string, _ int64) (*db.Project, error) {
				return nil, errors.New("Should not create projects from migration")
			},
			ghClientFactory,
			entityCreator,
		)
		githubProviderManager := ghmanager.NewGitHubProviderClassManager(
			&ratecache.NoopRestClientCache{},
			ghClientFactory,
			&cfg.Provider,
			&cfg.WebhookConfig,
			ghprov.NewFallbackTokenClient(cfg.Provider),
			cryptoEngine,
			store,
			ghProviders,
			propSvc,
			migrateMetrics,
			eventer,
		)

		providerManager.Register(githubProviderManager)

		if err := service.BackfillOrganizations(ctx, store, providerManager, entityCreator); err != nil {
			return fmt.Errorf("error while backfilling organizations: %w", err)
		}

		return nil
	},
}

func init() {
	migrateCmd.AddCommand(upCmd)
}
