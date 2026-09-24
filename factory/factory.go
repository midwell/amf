// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

/*
 * AMF Configuration Factory
 */

package factory

import (
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/omec-project/amf/logger"
	"go.yaml.in/yaml/v4"
)

var AmfConfig Config

const (
	AMFID_PATTERN   = "^[A-Fa-f0-9]{6}$"
	defaultAmfID    = "cafe00"
	defaultWebuiURI = "http://webui:5001"
)

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	content, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(content, &AmfConfig); err != nil {
		return err
	}
	// The lenient decode above is upstream's and stays lenient — this fork must keep starting
	// when upstream adds a key it does not model. The LI block is held to a stricter standard,
	// on its own, because a key dropped there lands on a default that fails unsafely and says
	// nothing: see strictLiBlock.
	//
	// **Recorded, not returned.** Returning it failed the whole configuration load, which stops
	// the AMF: the service-based interface, NGAP, registration with the network, every UE it
	// serves — over a typo in an optional subsystem. That is the outage this fork's own
	// `service/init.go` comment describes and refuses to cause for an unreadable keepalive
	// window, arrived at one frame earlier and in another package. It is also the louder half of
	// undetectability: a network function that will not start is visible to every operator and
	// peer, where a log line is visible only to whoever reads logs.
	//
	// The refusal is carried to the LI subsystem instead, which is the only party that can act
	// on it — it declines to intercept and reports the invalid configuration to the ADMF, at a
	// point where the reporting channel exists. See LiBlockError.
	liBlockErr = strictLiBlock(content)
	if AmfConfig.Configuration.AmfId == "" {
		AmfConfig.Configuration.AmfId = defaultAmfID
		logger.CfgLog.Infof("amfId not set in configuration file. Using %s", AmfConfig.Configuration.AmfId)
	}
	if AmfConfig.Configuration.WebuiUri == "" {
		AmfConfig.Configuration.WebuiUri = defaultWebuiURI
		logger.CfgLog.Infof("webuiUri not set in configuration file. Using %s", AmfConfig.Configuration.WebuiUri)
	}
	if AmfConfig.Configuration.KafkaInfo.EnableKafka == nil {
		enableKafka := true
		AmfConfig.Configuration.KafkaInfo.EnableKafka = &enableKafka
	}
	if AmfConfig.Configuration.Telemetry != nil && AmfConfig.Configuration.Telemetry.Enabled {
		if AmfConfig.Configuration.Telemetry.Ratio == nil {
			defaultRatio := 1.0
			AmfConfig.Configuration.Telemetry.Ratio = &defaultRatio
		}

		if AmfConfig.Configuration.Telemetry.OtlpEndpoint == "" {
			return fmt.Errorf("OTLP endpoint is not set in the configuration")
		}
	}
	if err = validateWebuiUri(AmfConfig.Configuration.WebuiUri); err != nil {
		return err
	}
	err = validateAmfId(AmfConfig.Configuration.AmfId)
	return err
}

func CheckConfigVersion() error {
	currentVersion := AmfConfig.GetVersion()

	if currentVersion != AMF_EXPECTED_CONFIG_VERSION {
		return fmt.Errorf("config version is [%s], but expected is [%s]",
			currentVersion, AMF_EXPECTED_CONFIG_VERSION)
	}

	logger.CfgLog.Infof("config version [%s]", currentVersion)

	return nil
}

func validateWebuiUri(uri string) error {
	parsedUrl, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return fmt.Errorf("unsupported scheme for webuiUri: %s", parsedUrl.Scheme)
	}
	if parsedUrl.Hostname() == "" {
		return fmt.Errorf("missing host in webuiUri")
	}
	return nil
}

func validateAmfId(amfId string) error {
	amfIdMatch, err := regexp.MatchString(AMFID_PATTERN, amfId)
	if err != nil {
		return fmt.Errorf("invalid amfId: %s. It should match the following pattern: `%s`", amfId, AMFID_PATTERN)
	}
	if !amfIdMatch {
		return fmt.Errorf("invalid amfId: %s. It should match the following pattern: `%s`", amfId, AMFID_PATTERN)
	}
	return nil
}
