// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * AMF Configuration Factory
 */

package factory

import (
	"time"

	"github.com/omec-project/util/logger"
)

const (
	AMF_EXPECTED_CONFIG_VERSION = "1.0.0"
)

type Config struct {
	Info          *Info          `yaml:"info"`
	Configuration *Configuration `yaml:"configuration"`
	Logger        *logger.Logger `yaml:"logger"`
	CfgLocation   string
}

type Info struct {
	Version     string `yaml:"version,omitempty"`
	Description string `yaml:"description,omitempty"`
}

const (
	AMF_DEFAULT_IPV4     = "127.0.0.18"
	AMF_DEFAULT_PORT     = "8000"
	AMF_DEFAULT_PORT_INT = 8000
	AMF_DEFAULT_NRFURI   = "https://127.0.0.10:8000"
)

type Mongodb struct {
	Name string `yaml:"name"`
	Url  string `yaml:"url"`
}

type KafkaInfo struct {
	EnableKafka *bool  `yaml:"enableKafka,omitempty"`
	BrokerUri   string `yaml:"brokerUri,omitempty"`
	BrokerPort  int    `yaml:"brokerPort,omitempty"`
	Topic       string `yaml:"topicName,omitempty"`
}

type TelemetryConfig struct {
	Enabled      bool     `yaml:"enabled,omitempty"`       // Optional; defaults to false
	OtlpEndpoint string   `yaml:"otlp_endpoint,omitempty"` // Mandatory if enabled=true
	Ratio        *float64 `yaml:"ratio,omitempty"`         // Optional; defaults to 1.0
}

type Configuration struct {
	AmfName                         string                    `yaml:"amfName,omitempty"`
	AmfId                           string                    `yaml:"amfId,omitempty"`
	AmfDBName                       string                    `yaml:"amfDBName,omitempty"`
	Mongodb                         *Mongodb                  `yaml:"mongodb,omitempty"`
	NgapIpList                      []string                  `yaml:"ngapIpList,omitempty"`
	NgapPort                        int                       `yaml:"ngappPort,omitempty"`
	SctpGrpcPort                    int                       `yaml:"sctpGrpcPort,omitempty"`
	Sbi                             *Sbi                      `yaml:"sbi,omitempty"`
	NetworkFeatureSupport5GS        *NetworkFeatureSupport5GS `yaml:"networkFeatureSupport5GS,omitempty"`
	ServiceNameList                 []string                  `yaml:"serviceNameList,omitempty"`
	SupportDnnList                  []string                  `yaml:"supportDnnList,omitempty"`
	NrfUri                          string                    `yaml:"nrfUri,omitempty"`
	WebuiUri                        string                    `yaml:"webuiUri"`
	Security                        *Security                 `yaml:"security,omitempty"`
	Li                              *Li                       `yaml:"li,omitempty"`
	NetworkName                     NetworkName               `yaml:"networkName,omitempty"`
	T3502Value                      int                       `yaml:"t3502Value,omitempty"`
	T3512Value                      int                       `yaml:"t3512Value,omitempty"`
	Non3gppDeregistrationTimerValue int                       `yaml:"non3gppDeregistrationTimerValue,omitempty"`
	T3513                           TimerValue                `yaml:"t3513"`
	T3522                           TimerValue                `yaml:"t3522"`
	T3550                           TimerValue                `yaml:"t3550"`
	T3560                           TimerValue                `yaml:"t3560"`
	T3565                           TimerValue                `yaml:"t3565"`
	Telemetry                       *TelemetryConfig          `yaml:"telemetry,omitempty"`

	EnableSctpLb             bool      `yaml:"enableSctpLb"`
	EnableDbStore            bool      `yaml:"enableDBStore"`
	EnableNrfCaching         bool      `yaml:"enableNrfCaching"`
	NrfCacheEvictionInterval int       `yaml:"nrfCacheEvictionInterval,omitempty"`
	KafkaInfo                KafkaInfo `yaml:"kafkaInfo,omitempty"`
	DebugProfilePort         int       `yaml:"debugProfilePort,omitempty"`
}

func (c *Configuration) Get5gsNwFeatSuppEnable() bool {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Enable
	}
	return true
}

func (c *Configuration) Get5gsNwFeatSuppImsVoPS() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.ImsVoPS
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppEmc() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Emc
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppEmf() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Emf
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppIwkN26() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.IwkN26
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppMpsi() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Mpsi
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppEmcN3() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.EmcN3
	}
	return 0
}

func (c *Configuration) Get5gsNwFeatSuppMcsi() uint8 {
	if c.NetworkFeatureSupport5GS != nil {
		return c.NetworkFeatureSupport5GS.Mcsi
	}
	return 0
}

type NetworkFeatureSupport5GS struct {
	Enable  bool  `yaml:"enable"`
	ImsVoPS uint8 `yaml:"imsVoPS"`
	Emc     uint8 `yaml:"emc"`
	Emf     uint8 `yaml:"emf"`
	IwkN26  uint8 `yaml:"iwkN26"`
	Mpsi    uint8 `yaml:"mpsi"`
	EmcN3   uint8 `yaml:"emcN3"`
	Mcsi    uint8 `yaml:"mcsi"`
}

type Sbi struct {
	Scheme       string `yaml:"scheme"`
	TLS          *TLS   `yaml:"tls"`
	RegisterIPv4 string `yaml:"registerIPv4,omitempty"` // IP that is registered at NRF.
	BindingIPv4  string `yaml:"bindingIPv4,omitempty"`  // IP used to run the server in the node.
	Port         int    `yaml:"port,omitempty"`
}

type TLS struct {
	PEM string `yaml:"pem,omitempty"`
	Key string `yaml:"key,omitempty"`
}

// Li configures the Lawful Interception IRI-POI. It is opt-in: when absent, LI
// is disabled and the AMF behaves exactly as before.
type Li struct {
	X1Listen string `yaml:"x1Listen"` // address for the X1 provisioning listener
	MDF2     string `yaml:"mdf2"`     // X2 delivery destination (host:port)
	NEID     string `yaml:"neId"`     // this network element's identifier
	Cert     string `yaml:"cert"`     // X0 LI PKI: this NE's certificate
	Key      string `yaml:"key"`      // its private key
	CACert   string `yaml:"caCert"`   // the LI CA trust anchor

	// Destinations declares DID→endpoint mappings for delivery destinations agreed
	// out of band. A task naming one of these DIDs is delivered to it exactly as if
	// the ADMF had provisioned it with CreateDestination; a destination provisioned
	// over X1 under the same DID takes precedence. Optional — an ADMF that
	// provisions its own destinations needs none of these, and `mdf2` above still
	// serves a task that names nothing resolvable.
	Destinations []LiDestination `yaml:"destinations,omitempty"`

	AdmfURL          string `yaml:"admfUrl"`          // ADMF X1 endpoint for NE-initiated issue reports (optional)
	AdmfID           string `yaml:"admfId"`           // responsible ADMF identifier (for reports)
	KeepaliveTimeout string `yaml:"keepaliveTimeout"` // duration; purge tasking if no X1 message within it (optional)

	// The X2/X3 keepalive mechanism of ETSI TS 103 221-2 clause 6.2.4, which is a
	// different mechanism from keepaliveTimeout above: that one is the X1 fail-safe
	// against an ADMF that goes quiet, this one detects a mediation function that
	// has stopped answering on the delivery connection. Hence the prefix — the two
	// read as halves of one setting otherwise, and they are not related at all.
	//
	// Enabled is a pointer so that "the operator said false" is distinct from "the
	// operator said nothing": unset means the mechanism runs, because the
	// specification requires it and TIME_P1 and TIME_P2 are given normatively (60
	// and 180 seconds), which is what an element configuring nothing must get.
	//
	// Setting it false is for a deployment whose mediation function does not
	// implement the MDF half of clause 6.2.4 — it will never acknowledge, and this
	// element would disconnect it every TIME_P2 and lose whatever was in flight. The
	// reference implementation this project interoperates with is such a peer.
	X2X3KeepaliveEnabled *bool  `yaml:"x2x3KeepaliveEnabled,omitempty"`
	X2X3KeepaliveTimeP1  string `yaml:"x2x3KeepaliveTimeP1,omitempty"` // duration; default 60s
	X2X3KeepaliveTimeP2  string `yaml:"x2x3KeepaliveTimeP2,omitempty"` // duration; default 180s

	// DeactivateAllTasks and RemoveAllDestinations carry what TS 103 221-1 leaves to
	// advance agreement between the operator and the agency: whether this element
	// performs a bulk deactivation of all its tasking, and whether it performs a bulk
	// removal of all its destinations.
	//
	// Both are tri-state. Unset — the pointer is nil — is "no agreement in advance",
	// the standard's own phrase, and yields the standard's own defaults: bulk
	// deactivation performed, bulk destination removal refused. They are pointers
	// rather than plain bools so that "the operator said false" is a state distinct
	// from "the operator said nothing", which for the first of them is the difference
	// between refusing to stop every interception on this element and doing it.
	DeactivateAllTasks    *bool `yaml:"deactivateAllTasks,omitempty"`
	RemoveAllDestinations *bool `yaml:"removeAllDestinations,omitempty"`
}

// LiDestination is one pre-shared delivery destination: the identifier an ADMF's tasks
// reference it by, and where it points. Its three fields are the ones CreateDestination
// carries, because the entry has to resolve identically to a provisioned one.
type LiDestination struct {
	DID          string `yaml:"did"`          // UUID, as the X1 schema requires of a DId
	DeliveryType string `yaml:"deliveryType"` // X2Only | X3Only | X2andX3
	Address      string `yaml:"address"`      // host:port
}

type Security struct {
	IntegrityOrder []string `yaml:"integrityOrder,omitempty"`
	CipheringOrder []string `yaml:"cipheringOrder,omitempty"`
}

type NetworkName struct {
	Full  string `yaml:"full"`
	Short string `yaml:"short,omitempty"`
}

type TimerValue struct {
	Enable        bool          `yaml:"enable"`
	ExpireTime    time.Duration `yaml:"expireTime"`
	MaxRetryTimes int           `yaml:"maxRetryTimes,omitempty"`
}

func (c *Config) GetVersion() string {
	if c.Info != nil && c.Info.Version != "" {
		return c.Info.Version
	}
	return ""
}
