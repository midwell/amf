// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
)

// captureSender records the xIRI PDUs delivered, standing in for the X2 client
// so tests can assert per-warrant delivery isolation.
type captureSender struct{ pdus []*x2x3.PDU }

func (c *captureSender) Send(p *x2x3.PDU) error {
	c.pdus = append(c.pdus, p)
	return nil
}

// targetIdentity is a fully-identified UE identity snapshot used across the
// mapping tests.
func targetIdentity() amfctx.UeIdentity {
	return amfctx.UeIdentity{
		Supi: "imsi-262019876543210",
		Pei:  "imeisv-3534250000000151",
		Gpsi: "msisdn-4915123456789",
	}
}

func TestTargetsOf(t *testing.T) {
	id := amfctx.UeIdentity{
		Supi: "imsi-262019876543210",
		Pei:  "imeisv-3534250000000151",
		Gpsi: "msisdn-4915123456789",
	}
	got := targetsOf(id)
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
	if ids := targetsOf(amfctx.UeIdentity{Supi: "suci-0-262-01-..."}); len(ids) != 0 {
		t.Errorf("unmappable SUPI produced identifiers: %+v", ids)
	}
}

func TestAMFRegistrationMapping(t *testing.T) {
	id := amfctx.UeIdentity{
		Supi: "imsi-262019876543210",
		Pei:  "imei-353425000000015",
		Gpsi: "msisdn-4915123456789",
	}
	reg := amfRegistration(id)
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

	g := fiveGGUTI(amfctx.UeIdentity{Tmsi: 42})
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

func TestRegistrationType(t *testing.T) {
	cases := map[uint8]iri.AMFRegistrationType{
		nasMessage.RegistrationType5GSInitialRegistration:          iri.RegTypeInitial,
		nasMessage.RegistrationType5GSMobilityRegistrationUpdating: iri.RegTypeMobility,
		nasMessage.RegistrationType5GSPeriodicRegistrationUpdating: iri.RegTypePeriodic,
		nasMessage.RegistrationType5GSEmergencyRegistration:        iri.RegTypeEmergency,
		nasMessage.RegistrationType5GSReserved:                     iri.RegTypeInitial, // unknown → initial
	}
	for nas, want := range cases {
		if got := registrationType(amfctx.UeIdentity{RegistrationType5GS: nas}); got != want {
			t.Errorf("registrationType(%d) = %d, want %d", nas, got, want)
		}
	}
}

// TestRegistrationEventDispatch checks that a mobility registration update maps
// to an AMFLocationUpdate and every other registration type to AMFRegistration.
func TestRegistrationEventDispatch(t *testing.T) {
	id := targetIdentity()

	id.RegistrationType5GS = nasMessage.RegistrationType5GSMobilityRegistrationUpdating
	if _, ok := registrationEvent(id).(iri.AMFLocationUpdate); !ok {
		t.Errorf("mobility update → %T, want AMFLocationUpdate", registrationEvent(id))
	}

	for _, rt := range []uint8{
		nasMessage.RegistrationType5GSInitialRegistration,
		nasMessage.RegistrationType5GSPeriodicRegistrationUpdating,
	} {
		id.RegistrationType5GS = rt
		reg, ok := registrationEvent(id).(iri.AMFRegistration)
		if !ok {
			t.Errorf("registration type %d → %T, want AMFRegistration", rt, registrationEvent(id))
			continue
		}
		if rt == nasMessage.RegistrationType5GSPeriodicRegistrationUpdating && reg.RegistrationType != iri.RegTypePeriodic {
			t.Errorf("periodic registration → regType %d, want %d", reg.RegistrationType, iri.RegTypePeriodic)
		}
	}
}

func TestDeregistrationMapping(t *testing.T) {
	id := targetIdentity()

	net := amfDeregistration(id, iri.DirNetworkInitiated, iri.AccessThreeGPP)
	if net.DeregistrationDirection != iri.DirNetworkInitiated || net.AccessType != iri.AccessThreeGPP {
		t.Errorf("network dereg = dir %d access %d", net.DeregistrationDirection, net.AccessType)
	}
	if supi, ok := net.SUPI.(iri.IMSI); !ok || supi != "262019876543210" {
		t.Errorf("dereg SUPI = %#v", net.SUPI)
	}

	ue2 := amfDeregistration(id, iri.DirUEInitiated, iri.AccessNonThreeGPP)
	if ue2.DeregistrationDirection != iri.DirUEInitiated || ue2.AccessType != iri.AccessNonThreeGPP {
		t.Errorf("ue dereg = dir %d access %d", ue2.DeregistrationDirection, ue2.AccessType)
	}
}

func TestUnsuccessfulRegistrationMapping(t *testing.T) {
	rec := amfUnsuccessfulRegistration(targetIdentity(), nasMessage.Cause5GMM5GSServicesNotAllowed)
	if rec.FailedProcedureType != iri.FailedRegistration {
		t.Errorf("failedProcedureType = %d, want FailedRegistration", rec.FailedProcedureType)
	}
	cause, ok := rec.FailureCause.(iri.FiveGMMCause)
	if !ok || cause != iri.FiveGMMCause(nasMessage.Cause5GMM5GSServicesNotAllowed) {
		t.Errorf("failureCause = %#v, want 5GMM %d", rec.FailureCause, nasMessage.Cause5GMM5GSServicesNotAllowed)
	}
}

func TestAccessTypeMapping(t *testing.T) {
	if accessType(models.ACCESSTYPE__3_GPP_ACCESS) != iri.AccessThreeGPP {
		t.Error("3GPP access mismapped")
	}
	if accessType(models.ACCESSTYPE_NON_3_GPP_ACCESS) != iri.AccessNonThreeGPP {
		t.Error("non-3GPP access mismapped")
	}
}

func TestTaskTargets(t *testing.T) {
	id := targetIdentity()
	hit := types.InterceptTask{Target: types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}}
	miss := types.InterceptTask{Target: types.TargetIdentifier{Type: types.TargetSUPI, Value: "000000000000000"}}
	if !taskTargets(hit, id) {
		t.Error("matching SUPI task not recognised")
	}
	if taskTargets(miss, id) {
		t.Error("non-matching task falsely recognised")
	}
}

func TestRegistered(t *testing.T) {
	dereg := &amfctx.AmfUe{State: map[models.AccessType]*fsm.State{
		models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(amfctx.Deregistered),
		models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(amfctx.Deregistered),
	}}
	if registered(dereg) {
		t.Error("deregistered UE reported as registered")
	}

	reg := &amfctx.AmfUe{State: map[models.AccessType]*fsm.State{
		models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(amfctx.Registered),
		models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(amfctx.Deregistered),
	}}
	if !registered(reg) {
		t.Error("registered UE (on 3GPP access) not recognised")
	}

	// A UE with no State map must not panic and is not registered.
	if registered(&amfctx.AmfUe{}) {
		t.Error("UE with nil State reported as registered")
	}
}

func TestIdentifierAssociationMapping(t *testing.T) {
	amfctx.AMF_Self().ServedGuamiList = []models.Guami{
		{PlmnId: models.PlmnIdNid{Mcc: "262", Mnc: "01"}, AmfId: "010203"},
	}
	t.Cleanup(func() { amfctx.AMF_Self().ServedGuamiList = nil })

	id := targetIdentity()
	id.Tmsi = 42

	assoc := amfIdentifierAssociation(id)
	if supi, ok := assoc.SUPI.(iri.IMSI); !ok || supi != "262019876543210" {
		t.Errorf("association SUPI = %#v", assoc.SUPI)
	}
	if assoc.GUTI.FiveGTMSI != 42 || assoc.GUTI.MCC != "262" {
		t.Errorf("association GUTI = %+v", assoc.GUTI)
	}

	deassoc := amfIdentifierDeassociation(id)
	if supi, ok := deassoc.SUPI.(iri.IMSI); !ok || supi != "262019876543210" {
		t.Errorf("deassociation SUPI = %#v", deassoc.SUPI)
	}
	if deassoc.GUTI.FiveGTMSI != 42 {
		t.Errorf("deassociation GUTI = %+v", deassoc.GUTI)
	}
}

// TestDeliveryIsolation checks multi-agency isolation: two agencies tasking the
// same target each receive exactly their own xIRI tagged with their own XID
// (no cross-delivery), and a CC-only warrant never leaks into IRI (X2) delivery.
func TestDeliveryIsolation(t *testing.T) {
	const (
		xidA  = "aaaaaaaa-0000-0000-0000-000000000001"
		xidB  = "bbbbbbbb-0000-0000-0000-000000000002"
		xidCC = "cccccccc-0000-0000-0000-000000000003"
	)
	target := types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"}
	st := store.New()
	st.Activate(types.InterceptTask{XID: xidA, Target: target, Products: []types.ProductType{types.ProductIRI}, State: types.TaskActive})
	st.Activate(types.InterceptTask{XID: xidB, Target: target, Products: []types.ProductType{types.ProductIRI}, State: types.TaskActive})
	st.Activate(types.InterceptTask{XID: xidCC, Target: target, Products: []types.ProductType{types.ProductCC}, State: types.TaskActive})

	capture := &captureSender{}
	active.Store(&subsystem{store: st, client: capture, iriCtx: iri.NewContext()})
	t.Cleanup(func() { active.Store(nil) })

	// Exercised through the exported entry point, so the snapshot is taken the
	// way a live NAS path takes it.
	ReportRegistration(&amfctx.AmfUe{
		Supi: "imsi-262019876543210",
		Pei:  "imeisv-3534250000000151",
		Gpsi: "msisdn-4915123456789",
	})

	if len(capture.pdus) != 2 {
		t.Fatalf("delivered %d xIRI PDUs, want 2 (the two IRI agencies; CC-only excluded)", len(capture.pdus))
	}
	count := map[[16]byte]int{}
	for _, p := range capture.pdus {
		count[p.XID]++
	}
	if count[parseXID(xidA)] != 1 || count[parseXID(xidB)] != 1 {
		t.Errorf("each IRI agency must receive its own xIRI exactly once; XID counts = %v", count)
	}
	if count[parseXID(xidCC)] != 0 {
		t.Error("CC-only warrant leaked into IRI (X2) delivery")
	}
}

// TestEncodeAllEvents verifies every AMF xIRI a reporter can produce encodes
// through the real TS 33.128 context without error — i.e. mandatory members are
// present and CHOICE arms are registered. This is the correctness check that a
// pure-mapping test cannot give.
func TestEncodeAllEvents(t *testing.T) {
	id := targetIdentity()
	ctx := iri.NewContext()
	events := map[string]any{
		"registration":            amfRegistration(id),
		"locationUpdate":          amfLocationUpdate(id),
		"deregistration":          amfDeregistration(id, iri.DirNetworkInitiated, iri.AccessThreeGPP),
		"unsuccessful":            amfUnsuccessfulRegistration(id, nasMessage.Cause5GMM5GSServicesNotAllowed),
		"startOfInterception":     amfStartOfInterception(id),
		"identifierAssociation":   amfIdentifierAssociation(id),
		"identifierDeassociation": amfIdentifierDeassociation(id),
	}
	for name, ev := range events {
		if _, err := iri.EncodeXIRI(ctx, ev); err != nil {
			t.Errorf("encode %s: %v", name, err)
		}
	}
}
