// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/types"
	"github.com/omec-project/openapi/v2/models"
)

func TestTargetsOf(t *testing.T) {
	ue := &amfctx.AmfUe{
		Supi: "imsi-262019876543210",
		Pei:  "imeisv-3534250000000151",
		Gpsi: "msisdn-4915123456789",
	}
	got := targetsOf(ue)
	want := map[types.TargetIdentifierType]string{
		types.TargetSUPI: "262019876543210",
		types.TargetPEI:  "3534250000000151",
		types.TargetGPSI: "4915123456789",
	}
	if len(got) != len(want) {
		t.Fatalf("targetsOf returned %d ids, want %d: %+v", len(got), len(want), got)
	}
	for _, id := range got {
		if want[id.Type] != id.Value {
			t.Errorf("identifier %s = %q, want %q", id.Type, id.Value, want[id.Type])
		}
	}

	// An unmappable/absent identifier is not emitted.
	if ids := targetsOf(&amfctx.AmfUe{Supi: "suci-0-262-01-..."}); len(ids) != 0 {
		t.Errorf("unmappable SUPI produced identifiers: %+v", ids)
	}
}

func TestAMFRegistrationMapping(t *testing.T) {
	ue := &amfctx.AmfUe{
		Supi: "imsi-262019876543210",
		Pei:  "imei-353425000000015",
		Gpsi: "msisdn-4915123456789",
	}
	reg := amfRegistration(ue)
	if reg.RegistrationResult != iri.RegResult3GPPAccess {
		t.Errorf("registrationResult = %d", reg.RegistrationResult)
	}
	if supi, ok := reg.SUPI.(iri.IMSI); !ok || supi != iri.IMSI("262019876543210") {
		t.Errorf("SUPI = %#v", reg.SUPI)
	}
	if pei, ok := reg.PEI.(iri.IMEI); !ok || pei != iri.IMEI("353425000000015") {
		t.Errorf("PEI = %#v", reg.PEI)
	}
	if gpsi, ok := reg.GPSI.(iri.MSISDN); !ok || gpsi != iri.MSISDN("4915123456789") {
		t.Errorf("GPSI = %#v", reg.GPSI)
	}
}

func TestFiveGGUTIDecode(t *testing.T) {
	// AmfId "010203" = RegionID(0x01)=1, SetID(bits 15..6)=8, Pointer(0x03)=3.
	amfctx.AMF_Self().ServedGuamiList = []models.Guami{
		{PlmnId: models.PlmnIdNid{Mcc: "262", Mnc: "01"}, AmfId: "010203"},
	}
	t.Cleanup(func() { amfctx.AMF_Self().ServedGuamiList = nil })

	g := fiveGGUTI(&amfctx.AmfUe{Tmsi: 42})
	if g.MCC != "262" || g.MNC != "01" {
		t.Errorf("PLMN = %s/%s, want 262/01", g.MCC, g.MNC)
	}
	if g.AMFRegionID != 1 || g.AMFSetID != 8 || g.AMFPointer != 3 {
		t.Errorf("AmfId decode = region %d set %d pointer %d, want 1/8/3", g.AMFRegionID, g.AMFSetID, g.AMFPointer)
	}
	if g.FiveGTMSI != 42 {
		t.Errorf("5G-TMSI = %d, want 42", g.FiveGTMSI)
	}
}

func TestParseXID(t *testing.T) {
	x := parseXID("50b93d1e-1b53-4d63-aacb-e4d99811bc0b")
	if x[0] != 0x50 || x[15] != 0x0b {
		t.Errorf("parseXID = % x", x)
	}
	if got := parseXID("not-a-uuid"); got != ([16]byte{}) {
		t.Errorf("bad XID = % x, want zero", got)
	}
}
