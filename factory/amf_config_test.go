// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 Canonical Ltd.
/*
 *  Tests for AMF Configuration Factory
 */

package factory

import (
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
