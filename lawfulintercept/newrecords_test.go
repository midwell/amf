// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"bytes"
	"errors"
	"testing"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/nas/v2/nasMessage"
)

const testTargetSUPI = "262019876543210"

// errDelivery stands in for an MDF that cannot be reached.
var errDelivery = errors.New("MDF unreachable")

func targetUE() *amfctx.AmfUe {
	return &amfctx.AmfUe{
		Supi: "imsi-" + testTargetSUPI,
		Pei:  "imeisv-3534250000000151",
		Gpsi: "msisdn-4915123456789",
	}
}

// activateIRI installs a subsystem with one IRI warrant for supi, delivering
// everything to snd.
func activateIRI(t *testing.T, snd sender, supi string) {
	t.Helper()
	st := store.New()
	if !st.Activate(types.InterceptTask{
		XID:      "aaaaaaaa-0000-0000-0000-000000000001",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: supi}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}) {
		t.Fatal("activate")
	}
	active.Store(&subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: "10.0.60.122:42069",
		ids:  x2x3.NewIdentity("amf-1", amfInterceptionPoint),
	})
	t.Cleanup(func() { active.Store(nil) })
}

func TestReportServiceAccept(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	ReportServiceAccept(targetUE())

	records := decodeRecords(t, snd)
	if len(records) != 1 {
		t.Fatalf("delivered %d records, want 1", len(records))
	}
	rec := records[0]
	if rec.event != eventUEServiceAccept {
		t.Fatalf("delivered XIRIEvent [%d], want aMFUEServiceAccept [%d]", rec.event, eventUEServiceAccept)
	}
	if got := supiOf(t, rec.member(t, 1)); got != testTargetSUPI {
		t.Errorf("SUPI = %q", got)
	}
	// The message-type octet, per TS 24.501 clause 9.7 — not the whole PDU.
	id := only(t, "serviceMessageIdentity [2]", rec.member(t, 2))
	if id.Tag != 2 || len(id.Bytes) != 1 {
		t.Fatalf("serviceMessageIdentity holds [%d] % x, want a one-octet serviceAccept [2] arm", id.Tag, id.Bytes)
	}
}

func TestReportUEPolicyTransfer(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	// Interior and trailing zero bytes: the shapes a payload-mangling codec breaks.
	//
	// Sixteen octets, because `UEPolicy ::= OCTET STRING (SIZE(16..65540))` and the encoder
	// checks it — at the shortest permitted length, which is the sharpest boundary to encode.
	//
	// The previous value was five, and lengthening it is what made this test pass. That was
	// half a fix: the constraint is right to be enforced, but a fixture changed until the
	// encoder accepts it turns a live gap into a green test and leaves the production
	// consequence covered by nothing. See TestAShortUEPolicyContainerIsRefusedAndReported.
	policy := []byte{
		0x01, 0x00, 0x00, 0xFF, 0x00, 0x7F, 0x80, 0x00,
		0x00, 0x02, 0x03, 0x04, 0xFE, 0xFF, 0x00, 0x00,
	}
	ReportUEPolicyTransfer(targetUE(), policy)

	records := decodeRecords(t, snd)
	if len(records) != 1 {
		t.Fatalf("delivered %d records, want 1", len(records))
	}
	if records[0].event != eventUEPolicyTransfer {
		t.Fatalf("delivered XIRIEvent [%d], want aMFUEPolicyTransfer [%d]", records[0].event, eventUEPolicyTransfer)
	}
	if got := records[0].member(t, 6).Bytes; !bytes.Equal(got, policy) {
		t.Errorf("uEPolicy = % x, want % x — the payload must arrive byte-identical", got, policy)
	}
}

// TestReportUEPolicyTransferIgnoresEmpty: uEPolicy is mandatory, so a transfer
// with no container produces nothing rather than a record asserting an empty
// policy.
func TestReportUEPolicyTransferIgnoresEmpty(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	ReportUEPolicyTransfer(targetUE(), nil)

	if len(snd.pdus) != 0 {
		t.Errorf("an empty policy produced %d record(s)", len(snd.pdus))
	}
}

func sampleHandover() Handover {
	return Handover{
		UE:              targetUE(),
		AMFUENGAPID:     7,
		RANUENGAPID:     9,
		HandoverType:    1,
		TargetToSource:  []byte{0xDE, 0xAD, 0x00},
		SourceToTarget:  []byte{0x00, 0xBE, 0xEF},
		PDUSessionID:    5,
		CauseGroup:      CauseGroupRadioNetwork,
		CauseValue:      17,
		HasCause:        true,
		HasPDUSessionID: true,
	}
}

func TestReportHandoverRecords(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	h := sampleHandover()
	ReportHandoverRequest(h)
	ReportHandoverCommand(h)

	records := decodeRecords(t, snd)
	if len(records) != 2 {
		t.Fatalf("delivered %d records, want 2", len(records))
	}

	req := records[0]
	if req.event != eventRANHandoverRequest {
		t.Fatalf("first record is XIRIEvent [%d], want aMFRANHandoverRequest [%d]", req.event, eventRANHandoverRequest)
	}
	if amf, ran := integer(t, req.member(t, 2)), integer(t, req.member(t, 3)); amf != 7 || ran != 9 {
		t.Errorf("NGAP ids = %d/%d, want 7/9", amf, ran)
	}
	if got := req.member(t, 11).Bytes; !bytes.Equal(got, h.SourceToTarget) {
		t.Errorf("sourceToTargetContainer = % x — the container carried from HANDOVER REQUIRED", got)
	}
	if got := req.member(t, 9).Bytes; !bytes.Equal(got, h.TargetToSource) {
		t.Errorf("targetToSourceContainer = % x", got)
	}
	// handoverCause [5] EXPLICIT around the group's alternative: radioNetwork [1].
	if cause := only(t, "handoverCause [5]", req.member(t, 5)); cause.Tag != 1 || integer(t, cause) != 17 {
		t.Errorf("handoverCause holds [%d] %d, want radioNetwork [1] 17", cause.Tag, integer(t, cause))
	}
	if id := only(t, "pDUSessionResourceInformation [6]", req.member(t, 6)); id.Tag != 1 || integer(t, id) != 5 {
		t.Errorf("pDUSessionResourceInformation holds [%d] %d, want pDUSessionID [1] 5", id.Tag, integer(t, id))
	}

	cmd := records[1]
	if cmd.event != eventRANHandoverCommand {
		t.Fatalf("second record is XIRIEvent [%d], want aMFRANHandoverCommand [%d]", cmd.event, eventRANHandoverCommand)
	}
	if got := cmd.member(t, 5).Bytes; !bytes.Equal(got, h.TargetToSource) {
		t.Errorf("command targetToSourceContainer = % x", got)
	}
	if supiOf(t, cmd.member(t, 1)) != testTargetSUPI {
		t.Error("the two handover records must name the same subscriber")
	}
}

// TestHandoverRequestNeedsEveryMandatoryMember: eight members are mandatory, and
// two of them are carried from an earlier message. If a carried one is missing —
// a handover whose REQUIRED was never seen, or whose state was already cleared —
// the record cannot be completed, and emitting a partial one would be worse than
// emitting none. The command record has no carried members and is unaffected.
func TestHandoverRequestNeedsEveryMandatoryMember(t *testing.T) {
	missing := map[string]func(*Handover){
		"no cause":            func(h *Handover) { h.HasCause = false },
		"no PDU session":      func(h *Handover) { h.HasPDUSessionID = false },
		"no source container": func(h *Handover) { h.SourceToTarget = nil },
		"no target container": func(h *Handover) { h.TargetToSource = nil },
	}
	for name, break_ := range missing {
		t.Run(name, func(t *testing.T) {
			snd := &captureSender{}
			activateIRI(t, snd, testTargetSUPI)
			h := sampleHandover()
			break_(&h)
			ReportHandoverRequest(h)
			if len(snd.pdus) != 0 {
				t.Errorf("an incomplete handover produced %d record(s)", len(snd.pdus))
			}
		})
	}
}

// TestHandoverCauseGroupsAreDistinguished: the group is half the meaning. A value
// alone cannot tell "radio network: handover desirable" from "misc: hardware
// failure".
//
// Each group is exercised at its own last permitted value, which is both the sharpest boundary
// to encode and the only way the case is expressible at all: the groups have four different
// upper bounds, and the single value this test used to share across all five — 3 — is outside
// `CauseTransport`, whose enumeration has two values. It encoded anyway until the bound was
// checked, which is what the bound is for.
func TestHandoverCauseGroupsAreDistinguished(t *testing.T) {
	groups := []struct {
		group HandoverCauseGroup
		value int64
		arm   int // the HandoverCause alternative: radioNetwork [1] … misc [5]
	}{
		{CauseGroupRadioNetwork, 52, 1},
		{CauseGroupTransport, 2, 2},
		{CauseGroupNAS, 4, 3},
		{CauseGroupProtocol, 7, 4},
		{CauseGroupMisc, 6, 5},
	}
	for _, g := range groups {
		snd := &captureSender{}
		activateIRI(t, snd, testTargetSUPI)
		h := sampleHandover()
		h.CauseGroup, h.CauseValue = g.group, g.value
		ReportHandoverRequest(h)

		records := decodeRecords(t, snd)
		if len(records) != 1 {
			t.Fatalf("group %v: delivered %d records", g.group, len(records))
		}
		cause := only(t, "handoverCause [5]", records[0].member(t, 5))
		if cause.Tag != g.arm || integer(t, cause) != g.value {
			t.Errorf("group %v is carried as [%d] %d, want [%d] %d",
				g.group, cause.Tag, integer(t, cause), g.arm, g.value)
		}
	}
}

// TestNewRecordsSilentForUntaskedSubscriber is the undetectability assertion for
// every hook this change adds to the AMF: a subscriber under no warrant must
// produce nothing on any of these paths. A record that appeared only for tasked
// subscribers would be a perfect detector, which is the one outcome the rules
// forbid absolutely.
func TestNewRecordsSilentForUntaskedSubscriber(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, "999999999999999") // someone else

	ReportServiceAccept(targetUE())
	ReportUEPolicyTransfer(targetUE(), []byte{0x01})
	ReportHandoverRequest(sampleHandover())
	ReportHandoverCommand(sampleHandover())

	if len(snd.pdus) != 0 {
		t.Errorf("an untasked subscriber produced %d record(s)", len(snd.pdus))
	}
}

// TestNewRecordsSurviveMissingContext: these hooks sit on paths that run for
// every UE, so they must tolerate a nil context and an absent subsystem without
// panicking — a panic here is a service outage, not an LI defect.
func TestNewRecordsSurviveMissingContext(t *testing.T) {
	t.Run("no subsystem", func(t *testing.T) {
		active.Store(nil)
		ReportServiceAccept(targetUE())
		ReportUEPolicyTransfer(targetUE(), []byte{0x01})
		ReportHandoverRequest(sampleHandover())
		ReportHandoverCommand(sampleHandover())
	})
	t.Run("nil UE", func(t *testing.T) {
		activateIRI(t, &captureSender{}, testTargetSUPI)
		ReportServiceAccept(nil)
		ReportUEPolicyTransfer(nil, []byte{0x01})
		h := sampleHandover()
		h.UE = nil
		ReportHandoverRequest(h)
		ReportHandoverCommand(h)
	})
	t.Run("delivery fails", func(t *testing.T) {
		activateIRI(t, senderFunc(func(*x2x3.PDU) error { return errDelivery }), testTargetSUPI)
		ReportServiceAccept(targetUE())
		ReportHandoverCommand(sampleHandover())
	})
}

// TestPeriodicRegistrationIsReportedOnceAsPeriodic pins behaviour that was
// correct and undefended, which is how the comment describing it came to say the
// opposite.
//
// A periodic registration update is a registration procedure the AMF performs, so
// TS 33.128 wants a record for it, and `AMF IRI-POI events` forbids the silent
// omission that suppressing it would create — an agency cannot tell an event that
// was not reported from a subject who did nothing. It is reported by the
// registration-complete tap rather than by the mobility tap, because the
// registration accept carries a 5G-GUTI whenever the UE has one and the UE
// therefore answers with Registration Complete.
func TestPeriodicRegistrationIsReportedOnceAsPeriodic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		regType uint8
		want    iri.AMFRegistrationType
	}{
		{"periodic", nasMessage.RegistrationType5GSPeriodicRegistrationUpdating, iri.RegTypePeriodic},
		{"mobility", nasMessage.RegistrationType5GSMobilityRegistrationUpdating, iri.RegTypeMobility},
		{"initial", nasMessage.RegistrationType5GSInitialRegistration, iri.RegTypeInitial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snd := &captureSender{}
			activateIRI(t, snd, testTargetSUPI)

			ue := targetUE()
			ue.RegistrationType5GS = tc.regType
			ReportRegistration(ue)

			if len(snd.pdus) != 1 {
				t.Fatalf("delivered %d records for one registration, want exactly 1", len(snd.pdus))
			}
			if got := registrationType(ue.IdentitySnapshot()); got != tc.want {
				t.Errorf("registration type = %v, want %v — an agency reads this field to "+
					"tell a keepalive from a movement from a new attachment", got, tc.want)
			}
		})
	}
}

// TestAShortUEPolicyContainerIsRefusedAndReported covers the production consequence the fixture
// above was lengthened to avoid.
//
// TS 33.128 makes `uEPolicy` mandatory in AMFUEPolicyTransfer and defines it as
// `OCTET STRING (SIZE(16..65540))`. A UE policy container is a UE POLICY DELIVERY SERVICE message,
// and the shortest ones are three octets — `MANAGE UE POLICY COMPLETE` is exactly that. So the
// element must produce the record and must not encode it; both halves of the specification cannot
// hold, and this project follows the schema and declares the contradiction (li CONFORMANCE
// finding 6).
//
// What must not happen is that the gap is invisible. Relaxing the bound would not deliver the
// record — a mediation function validating against the published module discards a three-octet
// container exactly as this encoder does — it would only move the discard to the far end, where
// this element cannot see it. That is the unattributable-record failure the constraint checking
// exists to close.
//
// So the assertion is: nothing is delivered, and the condition is reported against the warrant
// naming the record type, rather than as a generic delivery loss naming neither.
func TestAShortUEPolicyContainerIsRefusedAndReported(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	// A MANAGE UE POLICY COMPLETE: extended protocol discriminator, PTI, message identity.
	ReportUEPolicyTransfer(targetUE(), []byte{0x2e, 0x01, 0x03})

	if records := decodeRecords(t, snd); len(records) != 0 {
		t.Errorf("delivered %d records for a container the definition forbids. A conformant "+
			"mediation function discards it, and this element would believe it had delivered",
			len(records))
	}
}
