// Copyright (C) 2026 Intel Corporation
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"fmt"
	"os"
	"regexp"

	"github.com/omec-project/amf/logger"
	"github.com/omec-project/util/nfconfig"
)

var AmfConfig Config

const (
	AMFID_PATTERN = "^[A-Fa-f0-9]{6}$"
	defaultAmfID  = "cafe00"
)

// TODO: Support configuration update from REST api
func InitConfigFactory(f string) error {
	if err := nfconfig.LoadYAML(f, &AmfConfig); err != nil {
		return err
	}
	// The lenient decode above stays lenient — the AMF must keep starting on a configuration
	// carrying a key this version does not model. The LI block is held to a stricter standard,
	// on its own, because a key dropped there lands on a default that fails unsafely and says
	// nothing: see strictLiBlock.
	//
	// **Recorded, not returned.** Returning it would fail the whole configuration load, which
	// stops the AMF: the service-based interface, NGAP, registration with the network, every UE it
	// serves — over a typo in an optional subsystem. That is the outage the `service/init.go` LI
	// comment describes and refuses to cause for an unreadable keepalive window, arrived at one
	// frame earlier and in another package. It is also the louder half of undetectability: a
	// network function that will not start is visible to every operator and peer, where a log
	// line is visible only to whoever reads logs.
	//
	// The refusal is carried to the LI subsystem instead, which is the only party that can act
	// on it — it declines to intercept and reports the invalid configuration to the ADMF, at a
	// point where the reporting channel exists. See LiBlockError.
	//
	// nfconfig.LoadYAML does not hand back the bytes it decoded, so the block is read again.
	content, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	liBlockErr = strictLiBlock(content)
	if AmfConfig.Configuration.AmfId == "" {
		AmfConfig.Configuration.AmfId = defaultAmfID
		logger.CfgLog.Infof("amfId not set in configuration file. Using %s", AmfConfig.Configuration.AmfId)
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
	// Resolved after the telemetry checks so that error precedence matches the old code:
	// telemetry error, then webuiUri, then amfId.
	webuiUri, err := nfconfig.ResolveWebuiUri(AmfConfig.Configuration.WebuiUri, logger.CfgLog)
	if err != nil {
		return err
	}
	AmfConfig.Configuration.WebuiUri = webuiUri
	return validateAmfId(AmfConfig.Configuration.AmfId)
}

func CheckConfigVersion() error {
	return nfconfig.CheckVersion(AmfConfig.GetVersion(), AMF_EXPECTED_CONFIG_VERSION, logger.CfgLog)
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
