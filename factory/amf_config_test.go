// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
/*
 *  Tests for AMF Configuration Factory
 */

package factory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

func TestWebuiUrl(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		want       string
	}{
		{
			name:       "default webui URL",
			configFile: "../util/testdata/amfcfg.yaml",
			want:       "http://webui:5001",
		},
		{
			name:       "custom webui URL",
			configFile: "../util/testdata/amfcfg_with_custom_webui_url_and_amfid.yaml",
			want:       "https://myspecialwebui:5002",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origAmfConfig := AmfConfig
			t.Cleanup(func() { AmfConfig = origAmfConfig })

			if err := InitConfigFactory(tt.configFile); err != nil {
				t.Fatalf("Error in InitConfigFactory: %v", err)
			}

			got := AmfConfig.Configuration.WebuiUri
			if got != tt.want {
				t.Errorf("WebuiUri is not correct. got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestAmfId(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
		want       string
	}{
		{
			name:       "default AMF ID",
			configFile: "../util/testdata/amfcfg.yaml",
			want:       "cafe00",
		},
		{
			name:       "custom AMF ID",
			configFile: "../util/testdata/amfcfg_with_custom_webui_url_and_amfid.yaml",
			want:       "cafe01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origAmfConfig := AmfConfig
			t.Cleanup(func() { AmfConfig = origAmfConfig })

			if err := InitConfigFactory(tt.configFile); err != nil {
				t.Fatalf("Error in InitConfigFactory: %v", err)
			}

			got := AmfConfig.Configuration.AmfId
			if got != tt.want {
				t.Errorf("AmfId is not correct. got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestNoTelemetryConfig(t *testing.T) {
	origAmfConfig := AmfConfig
	t.Cleanup(func() { AmfConfig = origAmfConfig })
	if err := InitConfigFactory("../util/testdata/no_telemetry.yaml"); err != nil {
		t.Logf("Error in InitConfigFactory: %v", err)
	}

	if AmfConfig.Configuration.Telemetry != nil {
		t.Errorf("expected no telemetry configuration, but got: %v", AmfConfig.Configuration.Telemetry)
	}
}

func TestTelemetryConfigEnabled(t *testing.T) {
	origAmfConfig := AmfConfig
	t.Cleanup(func() { AmfConfig = origAmfConfig })
	if err := InitConfigFactory("../util/testdata/telemetry.yaml"); err != nil {
		t.Logf("Error in InitConfigFactory: %v", err)
	}

	if AmfConfig.Configuration.Telemetry == nil {
		t.Fatalf("expected telemetry configuration to be present, but it is nil")
	}

	if !AmfConfig.Configuration.Telemetry.Enabled {
		t.Errorf("expected telemetry to be enabled, but it is not")
	}

	if AmfConfig.Configuration.Telemetry.OtlpEndpoint == "" {
		t.Errorf("expected OTLP endpoint to be set, but it is empty")
	}

	if AmfConfig.Configuration.Telemetry.Ratio == nil || *AmfConfig.Configuration.Telemetry.Ratio != 0.4 {
		t.Errorf("expected telemetry ratio to be 0.4, but got: %v", AmfConfig.Configuration.Telemetry.Ratio)
	}
}

func TestTelemetryConfigEnabledNoRatioDefaultsTo1(t *testing.T) {
	origAmfConfig := AmfConfig
	t.Cleanup(func() { AmfConfig = origAmfConfig })
	if err := InitConfigFactory("../util/testdata/telemetry_no_ratio.yaml"); err != nil {
		t.Logf("Error in InitConfigFactory: %v", err)
	}

	if AmfConfig.Configuration.Telemetry == nil {
		t.Fatalf("expected telemetry configuration to be present, but it is nil")
	}

	if !AmfConfig.Configuration.Telemetry.Enabled {
		t.Errorf("expected telemetry to be enabled, but it is not")
	}

	if AmfConfig.Configuration.Telemetry.OtlpEndpoint == "" {
		t.Errorf("expected OTLP endpoint to be set, but it is empty")
	}

	if AmfConfig.Configuration.Telemetry.Ratio == nil || *AmfConfig.Configuration.Telemetry.Ratio != 1.0 {
		t.Errorf("expected telemetry ratio to be 1.0, but got: %v", AmfConfig.Configuration.Telemetry.Ratio)
	}
}

func TestTelemetryConfigEnabledRatio0Stays0(t *testing.T) {
	origAmfConfig := AmfConfig
	t.Cleanup(func() { AmfConfig = origAmfConfig })
	if err := InitConfigFactory("../util/testdata/telemetry_zero_ratio.yaml"); err != nil {
		t.Logf("Error in InitConfigFactory: %v", err)
	}

	if AmfConfig.Configuration.Telemetry == nil {
		t.Fatalf("expected telemetry configuration to be present, but it is nil")
	}

	if !AmfConfig.Configuration.Telemetry.Enabled {
		t.Errorf("expected telemetry to be enabled, but it is not")
	}

	if AmfConfig.Configuration.Telemetry.OtlpEndpoint == "" {
		t.Errorf("expected OTLP endpoint to be set, but it is empty")
	}

	if AmfConfig.Configuration.Telemetry.Ratio == nil || *AmfConfig.Configuration.Telemetry.Ratio != 0.0 {
		t.Errorf("expected telemetry ratio to be 0.0, but got: %v", AmfConfig.Configuration.Telemetry.Ratio)
	}
}

func TestTelemetryConfigEnabledNoEndpointReturnsError(t *testing.T) {
	origAmfConfig := AmfConfig
	t.Cleanup(func() { AmfConfig = origAmfConfig })
	if err := InitConfigFactory("../util/testdata/telemetry_no_endpoint.yaml"); err == nil {
		t.Errorf("expected error when OTLP endpoint is not set, but got none")
	} else {
		t.Logf("Received expected error: %v", err)
	}
}

func TestValidateWebuiUri(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		isValid bool
	}{
		{
			name:    "valid https URI with port",
			uri:     "https://webui:5001",
			isValid: true,
		},
		{
			name:    "valid http URI with port",
			uri:     "http://webui:5001",
			isValid: true,
		},
		{
			name:    "valid https URI without port",
			uri:     "https://webui",
			isValid: true,
		},
		{
			name:    "valid http URI without port",
			uri:     "http://webui.com",
			isValid: true,
		},
		{
			name:    "invalid host",
			uri:     "http://:8080",
			isValid: false,
		},
		{
			name:    "invalid scheme",
			uri:     "ftp://webui:21",
			isValid: false,
		},
		{
			name:    "missing scheme",
			uri:     "webui:9090",
			isValid: false,
		},
		{
			name:    "missing host",
			uri:     "https://",
			isValid: false,
		},
		{
			name:    "empty string",
			uri:     "",
			isValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWebuiUri(tc.uri)
			if err == nil && !tc.isValid {
				t.Errorf("expected URI: %s to be invalid", tc.uri)
			}
			if err != nil && tc.isValid {
				t.Errorf("expected URI: %s to be valid", tc.uri)
			}
		})
	}
}

func TestValidateAmfId(t *testing.T) {
	tests := []struct {
		name    string
		amfId   string
		isValid bool
	}{
		{
			name:    "valid amfId",
			amfId:   "cafe00",
			isValid: true,
		},
		{
			name:    "invalid amfId (shorter than 6 chars)",
			amfId:   "cafe",
			isValid: false,
		},
		{
			name:    "invalid amfId (longer 6 chars)",
			amfId:   "cafe00cafe00",
			isValid: false,
		},
		{
			name:    "invalid amfId (invalid chars)",
			amfId:   "cafe!0",
			isValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAmfId(tc.amfId)
			if err == nil && !tc.isValid {
				t.Errorf("expected amfId: %s to be invalid", tc.amfId)
			}
			if err != nil && tc.isValid {
				t.Errorf("expected amfId: %s to be valid", tc.amfId)
			}
		})
	}
}

// TestLiBulkSwitchesAreTriState covers the two keys that carry an agreement the standard
// leaves to the deployment, at the layer where an operator's `false` is at risk of becoming
// nothing at all.
//
// The third case is the one worth having: a value that is not a boolean must be refused,
// not read as unset. Unset is the permissive answer for bulk deactivation, so silently
// defaulting a typo would leave the element performing exactly the operation the operator
// wrote the key to withhold. It is the rule the UPF's config already applies to its
// keepalive window.
func TestLiBulkSwitchesAreTriState(t *testing.T) {
	li := func(extra string) string {
		return `configuration:
  li:
    x1Listen: ":8443"
    neId: amf-1` + extra + "\n"
	}

	t.Run("both switches carry through", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(li(`
    deactivateAllTasks: false
    removeAllDestinations: true`)), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := cfg.Configuration.Li.DeactivateAllTasks; got == nil || *got {
			t.Errorf("deactivateAllTasks = %v, want a stated false — a dropped restriction leaves "+
				"the element performing the operation the operator withheld", got)
		}
		if got := cfg.Configuration.Li.RemoveAllDestinations; got == nil || !*got {
			t.Errorf("removeAllDestinations = %v, want a stated true", got)
		}
	})

	t.Run("saying nothing is not saying false", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(li("")), &cfg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if cfg.Configuration.Li.DeactivateAllTasks != nil || cfg.Configuration.Li.RemoveAllDestinations != nil {
			t.Error("an li block that states no agreement must leave both unset, so the " +
				"standard's own defaults apply")
		}
	})

	t.Run("a value that is not a boolean is refused", func(t *testing.T) {
		var cfg Config
		if err := yaml.Unmarshal([]byte(li("\n    deactivateAllTasks: perhaps")), &cfg); err == nil {
			t.Errorf("an unparseable value was accepted as %v; it must be refused rather than "+
				"read as unset, which is the permissive answer",
				cfg.Configuration.Li.DeactivateAllTasks)
		}
	})
}

// TestLiBlockRefusesUnknownKeys covers the whole startup path, not strictLiBlock alone: the
// property is that a mistyped LI key stops the network function from starting, and that is only
// true if InitConfigFactory calls the check.
//
// Both keys below are chosen because their defaults fail *unsafely*. A dropped
// `keepaliveTimeout` leaves the X1 fail-safe off, so the element keeps tasking that nothing will
// ever reclaim; a dropped `admfUrl` leaves the fault channel a no-op, so nothing it is required to
// report — including a misconfiguration — reaches the ADMF. Neither is visible from outside: the
// element runs, answers X1, and looks provisioned.
func TestLiBlockRefusesUnknownKeys(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "amfcfg.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		return path
	}

	const good = `info:
  version: 1.0.0
configuration:
  li:
    x1Listen: ":8443"
    neId: amf-1
    admfUrl: https://admf:9443
    keepaliveTimeout: 30s
`

	t.Run("a conformant li block starts", func(t *testing.T) {
		orig := AmfConfig
		t.Cleanup(func() { AmfConfig = orig })

		if err := InitConfigFactory(write(t, good)); err != nil {
			t.Fatalf("a conformant li block was refused: %v", err)
		}
		if AmfConfig.Configuration.Li.KeepaliveTimeout != "30s" {
			t.Errorf("keepaliveTimeout = %q, want 30s — the strict pass must not disturb the decode",
				AmfConfig.Configuration.Li.KeepaliveTimeout)
		}
	})

	for _, tt := range []struct {
		name string
		typo string
	}{
		{"a misspelled fail-safe window", "keepaliveTimeut"},
		{"a misspelled ADMF endpoint", "admf_url"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			orig := AmfConfig
			t.Cleanup(func() { AmfConfig = orig })

			body := strings.Replace(good, "admfUrl", tt.typo, 1)
			if tt.typo == "keepaliveTimeut" {
				body = strings.Replace(good, "keepaliveTimeout", tt.typo, 1)
			}
			err := InitConfigFactory(write(t, body))
			if err == nil {
				t.Fatalf("%s was accepted, so the setting the operator wrote never reached the "+
					"element and its unsafe default stands with nothing saying so", tt.typo)
			}
			if !strings.Contains(err.Error(), tt.typo) {
				t.Errorf("the refusal does not name the key that was wrong: %v", err)
			}
		})
	}

	t.Run("a key outside the li block is still tolerated", func(t *testing.T) {
		orig := AmfConfig
		t.Cleanup(func() { AmfConfig = orig })

		// The scope of the check, asserted rather than assumed. This fork tracks an upstream
		// that adds configuration keys; if strictness leaked past the li block, the next
		// upstream field would stop every deployment carrying it from starting.
		body := strings.Replace(good, "configuration:\n", "configuration:\n  aKeyThisForkDoesNotModel: 1\n", 1)
		if err := InitConfigFactory(write(t, body)); err != nil {
			t.Fatalf("an unmodelled key outside the li block was refused, which would stop this "+
				"fork starting on the next upstream field: %v", err)
		}
	})

	t.Run("no li block at all", func(t *testing.T) {
		orig := AmfConfig
		t.Cleanup(func() { AmfConfig = orig })

		if err := InitConfigFactory(write(t, "info:\n  version: 1.0.0\nconfiguration:\n  amfName: AMF\n")); err != nil {
			t.Fatalf("a configuration without interception was refused: %v", err)
		}
	})
}
