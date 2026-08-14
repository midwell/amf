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
		mdf2: "10.0.60.122:42069", iriCtx: iri.NewContext(),
		ids: x2x3.NewIdentity("amf-1", amfInterceptionPoint),
	})
	t.Cleanup(func() { active.Store(nil) })
}

func decodeEvents(t *testing.T, snd *captureSender) []any {
	t.Helper()
	out := make([]any, 0, len(snd.pdus))
	for _, p := range snd.pdus {
		var payload iri.XIRIPayload
		if _, err := iri.NewContext().Decode(p.Payload, &payload); err != nil {
			t.Fatalf("decode xIRI: %v", err)
		}
		out = append(out, payload.Event)
	}
	return out
}

// supiFrom digs the SUPI out of a UserIdentifiers list, which is how the newer
// records carry identity — one list rather than three optional members.
func supiFrom(t *testing.T, u iri.UserIdentifiers) string {
	t.Helper()
	for _, id := range u.FiveGS.IDs {
		if arm, ok := id.(iri.SubscriberSUPI); ok {
			if imsi, ok := arm.Value.(iri.IMSI); ok {
				return string(imsi)
			}
		}
	}
	t.Fatalf("no sUPI in %#v", u.FiveGS.IDs)
	return ""
}

func TestReportServiceAccept(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	ReportServiceAccept(targetUE())

	events := decodeEvents(t, snd)
	if len(events) != 1 {
		t.Fatalf("delivered %d records, want 1", len(events))
	}
	rec, ok := events[0].(iri.AMFUEServiceAccept)
	if !ok {
		t.Fatalf("decoded a %T, want AMFUEServiceAccept", events[0])
	}
	if got := supiFrom(t, rec.UserIdentifiers); got != testTargetSUPI {
		t.Errorf("SUPI = %q", got)
	}
	// The message-type octet, per TS 24.501 clause 9.7 — not the whole PDU.
	id, ok := rec.ServiceMessageIdentity.(iri.ServiceAcceptIdentity)
	if !ok || len(id) != 1 {
		t.Fatalf("serviceMessageIdentity = %#v, want a one-octet serviceAccept arm", rec.ServiceMessageIdentity)
	}
}

func TestReportUEPolicyTransfer(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	// Interior and trailing zero bytes: the shapes a payload-mangling codec breaks.
	policy := []byte{0x01, 0x00, 0x00, 0xFF, 0x00}
	ReportUEPolicyTransfer(targetUE(), policy)

	events := decodeEvents(t, snd)
	if len(events) != 1 {
		t.Fatalf("delivered %d records, want 1", len(events))
	}
	rec := events[0].(iri.AMFUEPolicyTransfer) //nolint:errcheck // asserted below
	if !bytes.Equal(rec.UEPolicy, policy) {
		t.Errorf("uEPolicy = % x, want % x — the payload must arrive byte-identical", rec.UEPolicy, policy)
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

	events := decodeEvents(t, snd)
	if len(events) != 2 {
		t.Fatalf("delivered %d records, want 2", len(events))
	}

	req, ok := events[0].(iri.AMFRANHandoverRequest)
	if !ok {
		t.Fatalf("first record is %T, want AMFRANHandoverRequest", events[0])
	}
	if req.AMFUENGAPID != 7 || req.RANUENGAPID != 9 {
		t.Errorf("NGAP ids = %d/%d, want 7/9", req.AMFUENGAPID, req.RANUENGAPID)
	}
	if !bytes.Equal(req.SourceToTargetContainer, h.SourceToTarget) {
		t.Errorf("sourceToTargetContainer = % x — the container carried from HANDOVER REQUIRED", req.SourceToTargetContainer)
	}
	if !bytes.Equal(req.TargetToSourceContainer, h.TargetToSource) {
		t.Errorf("targetToSourceContainer = % x", req.TargetToSourceContainer)
	}
	if cause, isRadio := req.HandoverCause.(iri.CauseRadioNetwork); !isRadio || cause != 17 {
		t.Errorf("handoverCause = %#v, want CauseRadioNetwork(17)", req.HandoverCause)
	}
	if req.PDUSessionResourceInformation.PDUSessionID != 5 {
		t.Errorf("pDUSessionResourceInformation = %+v", req.PDUSessionResourceInformation)
	}

	cmd, ok := events[1].(iri.AMFRANHandoverCommand)
	if !ok {
		t.Fatalf("second record is %T, want AMFRANHandoverCommand", events[1])
	}
	if !bytes.Equal(cmd.TargetToSourceContainer, h.TargetToSource) {
		t.Errorf("command targetToSourceContainer = % x", cmd.TargetToSourceContainer)
	}
	if supiFrom(t, cmd.UserIdentifiers) != testTargetSUPI {
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
func TestHandoverCauseGroupsAreDistinguished(t *testing.T) {
	groups := []struct {
		group HandoverCauseGroup
		want  any
	}{
		{CauseGroupRadioNetwork, iri.CauseRadioNetwork(3)},
		{CauseGroupTransport, iri.CauseTransport(3)},
		{CauseGroupNAS, iri.CauseNas(3)},
		{CauseGroupProtocol, iri.CauseProtocol(3)},
		{CauseGroupMisc, iri.CauseMisc(3)},
	}
	for _, g := range groups {
		snd := &captureSender{}
		activateIRI(t, snd, testTargetSUPI)
		h := sampleHandover()
		h.CauseGroup, h.CauseValue = g.group, 3
		ReportHandoverRequest(h)

		events := decodeEvents(t, snd)
		if len(events) != 1 {
			t.Fatalf("group %v: delivered %d records", g.group, len(events))
		}
		rec := events[0].(iri.AMFRANHandoverRequest) //nolint:errcheck // asserted by construction
		if rec.HandoverCause != g.want {
			t.Errorf("group %v decoded as %#v, want %#v", g.group, rec.HandoverCause, g.want)
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
