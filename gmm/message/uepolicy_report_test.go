// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"bytes"
	"testing"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/amf/logger"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
)

// relayingUe is the minimum RanUe SendDLNASTransport dereferences: a UE with an access type,
// a RAN, and the loggers every path on the way through writes to.
func relayingUe(t *testing.T) *context.RanUe {
	t.Helper()

	ran := context.NewAmfRanDefault()
	ran.AnType = models.ACCESSTYPE__3_GPP_ACCESS
	ran.Log = logger.NgapLog

	amfUe := &context.AmfUe{
		GmmLog: logger.GmmLog,
		AllowedNssai: map[models.AccessType][]models.AllowedSnssai{
			models.ACCESSTYPE__3_GPP_ACCESS: {{AllowedSnssai: models.Snssai{Sst: 1}}},
		},
	}

	return &context.RanUe{
		AmfUe:       amfUe,
		Ran:         ran,
		AmfUeNgapId: 1,
		RanUeNgapId: 2,
		Log:         logger.NgapLog,
	}
}

// TestADownlinkUEPolicyContainerIsReported is the direction that produced no record at all.
//
// TS 33.128 defines AMFUEPolicyTransfer as the record of this AMF passing a UE policy
// container, and it passes them both ways: uplink to the PCF, and downlink to the UE from two
// separate N1N2 relay paths. Only the uplink was hooked — so an agency's account of a tasked
// subject's policy exchange showed one side of a two-sided conversation, with nothing to say
// the other side was missing.
//
// The hook is on the send rather than beside the two call sites, which is the third time this
// shape has cost a record: a hook placed beside one caller is not inherited by the next.
func TestADownlinkUEPolicyContainerIsReported(t *testing.T) {
	var got []byte
	reported := 0

	restore := reportUEPolicyTransfer
	reportUEPolicyTransfer = func(_ *context.AmfUe, policy []byte) {
		reported++
		got = append([]byte(nil), policy...)
	}
	t.Cleanup(func() { reportUEPolicyTransfer = restore })

	ue := relayingUe(t)

	policy := []byte{0x11, 0x22, 0x33}
	SendDLNASTransport(ue, models.ACCESSTYPE__3_GPP_ACCESS,
		nasMessage.PayloadContainerTypeUEPolicy, policy, 0, 0, nil, 0)

	if reported != 1 {
		t.Fatalf("a downlink UE policy container was reported %d times, want 1: the AMF performed "+
			"a transfer TS 33.128 defines a record for and produced none", reported)
	}
	if !bytes.Equal(got, policy) {
		t.Errorf("the record carries %v, want the container that was sent %v", got, policy)
	}
}

// TestADownlinkContainerOfAnotherKindIsNotReported keeps the gate: the record is about UE
// policy, and reporting an SM or SMS container as one would tell an agency about an exchange
// that did not happen.
func TestADownlinkContainerOfAnotherKindIsNotReported(t *testing.T) {
	reported := 0

	restore := reportUEPolicyTransfer
	reportUEPolicyTransfer = func(*context.AmfUe, []byte) { reported++ }
	t.Cleanup(func() { reportUEPolicyTransfer = restore })

	ue := relayingUe(t)

	for _, kind := range []uint8{
		nasMessage.PayloadContainerTypeN1SMInfo,
		nasMessage.PayloadContainerTypeSMS,
		nasMessage.PayloadContainerTypeLPP,
	} {
		SendDLNASTransport(ue, models.ACCESSTYPE__3_GPP_ACCESS, kind, []byte{0x01}, 0, 0, nil, 0)
	}

	if reported != 0 {
		t.Errorf("%d containers of other kinds were reported as UE policy transfers", reported)
	}
}
