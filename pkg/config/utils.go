// SPDX-FileCopyrightText: Copyright 2023 The Minder Authors
// SPDX-License-Identifier: Apache-2.0

// Package config contains the configuration for the minder cli and server
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// FlagInst is a function that creates a flag and returns a pointer to the value
type FlagInst[V any] func(name string, value V, usage string) *V

// FlagInstShort is a function that creates a flag and returns a pointer to the value
type FlagInstShort[V any] func(name, shorthand string, value V, usage string) *V

// BindConfigFlag is a helper function that binds a configuration value to a flag.
//
// Parameters:
// - v: The viper.Viper object used to retrieve the configuration value.
// - flags: The pflag.FlagSet object used to retrieve the flag value.
// - viperPath: The path used to retrieve the configuration value from Viper.
// - cmdLineArg: The flag name used to check if the flag has been set and to retrieve its value.
// - help: The help text for the flag.
// - defaultValue: A default value used to determine the type of the flag (string, int, etc.).
// - binder: A function that creates a flag and returns a pointer to the value.
func BindConfigFlag[V any](
	v *viper.Viper,
	flags *pflag.FlagSet,
	viperPath string,
	cmdLineArg string,
	defaultValue V,
	help string,
	binder FlagInst[V],
) error {
	binder(cmdLineArg, defaultValue, help)
	return doViperBind[V](v, flags, viperPath, cmdLineArg, defaultValue)
}

// BindConfigFlagWithShort is a helper function that binds a configuration value to a flag.
//
// Parameters:
// - v: The viper.Viper object used to retrieve the configuration value.
// - flags: The pflag.FlagSet object used to retrieve the flag value.
// - viperPath: The path used to retrieve the configuration value from Viper.
// - cmdLineArg: The flag name used to check if the flag has been set and to retrieve its value.
// - short: The short name for the flag.
// - help: The help text for the flag.
// - defaultValue: A default value used to determine the type of the flag (string, int, etc.).
// - binder: A function that creates a flag and returns a pointer to the value.
func BindConfigFlagWithShort[V any](
	v *viper.Viper,
	flags *pflag.FlagSet,
	viperPath string,
	cmdLineArg string,
	short string,
	defaultValue V,
	help string,
	binder FlagInstShort[V],
) error {
	binder(cmdLineArg, short, defaultValue, help)
	return doViperBind[V](v, flags, viperPath, cmdLineArg, defaultValue)
}

func doViperBind[V any](
	v *viper.Viper,
	flags *pflag.FlagSet,
	viperPath string,
	cmdLineArg string,
	defaultValue V,
) error {
	v.SetDefault(viperPath, defaultValue)
	if err := v.BindPFlag(viperPath, flags.Lookup(cmdLineArg)); err != nil {
		return fmt.Errorf("failed to bind flag %s to viper path %s: %w", cmdLineArg, viperPath, err)
	}

	return nil
}

// GetConfigFileData returns the data from the given configuration file.
func GetConfigFileData(cfgFilePath string) (interface{}, error) {
	cfgFileBytes, err := os.ReadFile(filepath.Clean(cfgFilePath))
	if err != nil {
		return nil, err
	}

	var cfgFileData interface{}
	err = yaml.Unmarshal(cfgFileBytes, &cfgFileData)
	if err != nil {
		return nil, err
	}

	return cfgFileData, nil
}

// GetKeysWithNullValueFromYAML returns a list of paths to null values in the given configuration data.
func GetKeysWithNullValueFromYAML(data interface{}, currentPath string) []string {
	var keysWithNullValue []string
	switch v := data.(type) {
	// gopkg yaml.v2 unmarshals YAML maps into map[interface{}]interface{}.
	// gopkg yaml.v3 unmarshals YAML maps into map[string]interface{} or map[interface{}]interface{}.
	case map[interface{}]interface{}:
		for key, value := range v {
			var newPath string
			if key == nil {
				newPath = fmt.Sprintf("%s.null", currentPath) // X.<nil> is not a valid path
			} else {
				newPath = fmt.Sprintf("%s.%v", currentPath, key)
			}
			if value == nil {
				keysWithNullValue = append(keysWithNullValue, newPath)
			} else {
				keysWithNullValue = append(keysWithNullValue, GetKeysWithNullValueFromYAML(value, newPath)...)
			}
		}

	case map[string]interface{}:
		for key, value := range v {
			newPath := fmt.Sprintf("%s.%v", currentPath, key)
			if value == nil {
				keysWithNullValue = append(keysWithNullValue, newPath)
			} else {
				keysWithNullValue = append(keysWithNullValue, GetKeysWithNullValueFromYAML(value, newPath)...)
			}
		}

	case []interface{}:
		for i, item := range v {
			newPath := fmt.Sprintf("%s[%d]", currentPath, i)
			if item == nil {
				keysWithNullValue = append(keysWithNullValue, newPath)
			} else {
				keysWithNullValue = append(keysWithNullValue, GetKeysWithNullValueFromYAML(item, newPath)...)
			}
		}
	}

	return keysWithNullValue
}

// ReadConfigFromViper reads the configuration from the given Viper instance.
// This will return the already-parsed and validated configuration, or an error.
func ReadConfigFromViper[CFG any](v *viper.Viper) (*CFG, error) {
	var cfg CFG
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SetViperStructDefaults recursively sets the viper default values for the given struct.
//
// Per https://github.com/spf13/viper/issues/188#issuecomment-255519149, and
// https://github.com/spf13/viper/issues/761, we need to call viper.SetDefault() for each
// field in the struct to be able to use env var overrides.  This also lets us use the
// struct as the source of default values, so yay?
func SetViperStructDefaults(v *viper.Viper, prefix string, s any) {
	structType := reflect.TypeOf(s)

	for i := 0; i < structType.NumField(); i++ {
		field := structType.Field(i)
		if unicode.IsLower([]rune(field.Name)[0]) {
			// Skip private fields
			continue
		}
		if field.Tag.Get("mapstructure") == "" {
			// Error, need a tag
			panic(fmt.Sprintf("Untagged config struct field %q", field.Name))
		}

		var valueName string
		// Check if the tag is "squash" and if so, don't add the field name to the prefix
		if field.Tag.Get("mapstructure") == ",squash" {
			if strings.HasSuffix(prefix, ".") {
				valueName = strings.ToLower(prefix[:len(prefix)-1])
			} else {
				valueName = strings.ToLower(prefix)
			}
		} else {
			valueName = strings.ToLower(prefix + field.Tag.Get("mapstructure"))
		}
		fieldType := field.Type

		// Extract a default value the `default` struct tag
		// we don't support all value types yet, but we can add them as needed
		value := field.Tag.Get("default")

		// Dereference one level of pointers, if present
		if fieldType.Kind() == reflect.Ptr {
			fieldType = fieldType.Elem()
		}

		if fieldType.Kind() == reflect.Struct {
			SetViperStructDefaults(v, valueName+".", reflect.Zero(fieldType).Interface())
			if _, ok := field.Tag.Lookup("default"); ok {
				overrideViperStructDefaults(v, valueName, value)
			}
			continue
		}

		defaultValue := getDefaultValue(field, value, valueName)
		if err := v.BindEnv(strings.ToUpper(valueName)); err != nil {
			panic(fmt.Sprintf("Failed to bind %q to env var: %v", valueName, err))
		}
		v.SetDefault(valueName, defaultValue)
	}
}

func overrideViperStructDefaults(v *viper.Viper, prefix string, newDefaults string) {
	overrides := map[string]any{}
	if err := json.Unmarshal([]byte(newDefaults), &overrides); err != nil {
		panic(fmt.Sprintf("Failed to parse overrides in %q: %v", prefix, err))
	}

	for key, value := range overrides {
		// TODO: we don't do any fancy type checking here, so this could blow up later.
		// I expect it will blow up at config-parse time, which should be earlier enough.
		v.SetDefault(prefix+"."+key, value)
	}
}

func getDefaultValueForInt64(value string) (any, error) {
	var defaultValue any
	var err error

	defaultValue, err = strconv.ParseInt(value, 0, 0)
	if err == nil {
		return defaultValue, nil
	}

	// Try to parse it as a time.Duration
	var parseErr error
	defaultValue, parseErr = time.ParseDuration(value)
	if parseErr == nil {
		return defaultValue, nil
	}

	// Return the original error, not time.ParseDuration's error
	return nil, err
}

func getDefaultValue(field reflect.StructField, value string, valueName string) any {
	defaultValue := reflect.Zero(field.Type).Interface()
	var err error // We handle errors at the end of the switch
	//nolint:exhaustive
	switch field.Type.Kind() {
	case reflect.String:
		defaultValue = value
	case reflect.Int64:
		defaultValue, err = getDefaultValueForInt64(value)
	case reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int,
		reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8, reflect.Uint:
		defaultValue, err = strconv.ParseInt(value, 0, 0)
	case reflect.Float64:
		defaultValue, err = strconv.ParseFloat(value, 64)
	case reflect.Bool:
		defaultValue, err = strconv.ParseBool(value)
	case reflect.Slice:
		defaultValue = nil
	case reflect.Map:
		defaultValue = nil
	default:
		err = fmt.Errorf("unhandled type %s", field.Type)
	}
	if err != nil {
		// This is effectively a compile-time error, so exit early
		panic(fmt.Sprintf("Bad value for field %q (%s): %q", valueName, field.Type, err))
	}
	return defaultValue
}
