// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"strings"
	"testing"
	"time"

	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// activateIRIReporting is activateIRI with a fault channel pointed at an ADMF stub, so a test
// can assert both halves of a condition: what the record carries, and what was said about it.
func activateIRIReporting(t *testing.T, snd sender, supi, admfURL string) {
	t.Helper()
	st := store.New()
	if !st.Activate(types.InterceptTask{
		XID:      testSubstitutionXID,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: supi}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}) {
		t.Fatal("activate")
	}
	active.Store(&subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: "10.0.60.122:42069", iriCtx: iri.NewContext(),
		ids:      x2x3.NewIdentity("amf-1", amfInterceptionPoint),
		reporter: x1.NewReporter(admfURL, "admf-1", "amf-1", nil),
	})
	t.Cleanup(func() { active.Store(nil) })
}

const testSubstitutionXID = "aaaaaaaa-0000-0000-0000-000000000001"

// awaitReport waits for the ADMF stub to have received a body containing want, and returns
// everything it received.
func awaitReport(t *testing.T, admf *admfStub, want string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		joined := strings.Join(admf.received(), "\n")
		if strings.Contains(joined, want) {
			return joined
		}
		time.Sleep(20 * time.Millisecond)
	}

	return strings.Join(admf.received(), "\n")
}

// TestASubstitutedCauseIsDistinguishableFromAGenuineUnspecified is the assertion that makes D2's
// substitution honest rather than merely defensible.
//
// The two records are byte-identical in the field that matters: a handover whose cause this
// element cannot express carries `unspecified`, and so does a handover whose cause the network
// genuinely gave as unspecified. Nothing in the record distinguishes them and nothing can — the
// CHOICE has no arm for "a cause I could not carry". So the fault report is the whole of the
// difference, and if it were absent, or present in both cases, an agency reading the product
// would have no way to tell a network that gave no reason from one that gave a reason this
// element dropped.
func TestASubstitutedCauseIsDistinguishableFromAGenuineUnspecified(t *testing.T) {
	admf := newADMFStub(t)
	snd := &captureSender{}
	activateIRIReporting(t, snd, testTargetSUPI, admf.srv.URL)

	// First the genuine one: the network gave `unspecified`, and this element has nothing to
	// add. Asserted before the substituted case so a report appearing here cannot be confused
	// with the one the substitution is supposed to produce.
	genuine := sampleHandover()
	genuine.CauseValue = int64(iri.CauseRadioNetworkUnspecified)
	genuine.CauseSubstituted = false
	ReportHandoverRequest(genuine)

	// Nothing to wait for, so give the asynchronous path a moment to be wrong in.
	time.Sleep(200 * time.Millisecond)
	if joined := strings.Join(admf.received(), "\n"); strings.Contains(joined, "recordValueSubstituted") {
		t.Errorf("a cause the network itself gave as unspecified was reported as substituted, "+
			"which spends the one signal that distinguishes the two:\n%s", joined)
	}

	// Then the substituted one, carrying the same value.
	substituted := sampleHandover()
	substituted.CauseValue = int64(iri.CauseRadioNetworkUnspecified)
	substituted.CauseSubstituted = true
	ReportHandoverRequest(substituted)

	events := decodeEvents(t, snd)
	if len(events) != 2 {
		t.Fatalf("delivered %d records, want 2 — the substitution must not cost the record", len(events))
	}
	for i, ev := range events {
		req, ok := ev.(iri.AMFRANHandoverRequest)
		if !ok {
			t.Fatalf("record %d is %T, want AMFRANHandoverRequest", i, ev)
		}
		cause, isRadio := req.HandoverCause.(iri.CauseRadioNetwork)
		if !isRadio || cause != iri.CauseRadioNetworkUnspecified {
			t.Errorf("record %d carries handoverCause %#v, want CauseRadioNetwork(%d): the two "+
				"records must be indistinguishable in the record, which is what makes the report "+
				"the only signal", i, req.HandoverCause, iri.CauseRadioNetworkUnspecified)
		}
	}

	joined := awaitReport(t, admf, "recordValueSubstituted")
	if !strings.Contains(joined, "recordValueSubstituted") {
		t.Fatalf("a handover cause this element could not express was carried as `unspecified` "+
			"and nothing said so, so the agency's product asserts the network gave no reason:\n%s",
			joined)
	}
}

// TestTheSubstitutionReportNamesNoTargetAndNoWarrant: which causes this element can express is a
// property of the element and of the release its record definitions come from, not of any
// warrant — so the report is element-scoped, and an element-scoped report that named a subject
// would put a target identity on the X1 interface for a condition that does not concern one.
//
// Checked against the identifiers the fixture actually uses, because a report naming no subject
// is easy to write and easy to lose: the description is assembled from a format string near a
// Handover value that has all three identifiers on it.
func TestTheSubstitutionReportNamesNoTargetAndNoWarrant(t *testing.T) {
	admf := newADMFStub(t)
	snd := &captureSender{}
	activateIRIReporting(t, snd, testTargetSUPI, admf.srv.URL)

	h := sampleHandover()
	h.CauseValue = int64(iri.CauseRadioNetworkUnspecified)
	h.CauseSubstituted = true
	ReportHandoverRequest(h)

	joined := awaitReport(t, admf, "recordValueSubstituted")
	if !strings.Contains(joined, "recordValueSubstituted") {
		t.Fatalf("no substitution report arrived:\n%s", joined)
	}

	id := targetIdentity()
	for what, value := range map[string]string{
		"the target's SUPI":   id.Supi,
		"the target's PEI":    id.Pei,
		"the target's GPSI":   id.Gpsi,
		"the warrant's XID":   testSubstitutionXID,
		"an xIRI target tag":  "<ns1:targetIdentifier",
		"an xIRI xid element": "<ns1:xId",
	} {
		if value != "" && strings.Contains(joined, value) {
			t.Errorf("the substitution report names %s (%q): the condition concerns which values "+
				"this element can express, which is true of the element whoever it is intercepting",
				what, value)
		}
	}
}
