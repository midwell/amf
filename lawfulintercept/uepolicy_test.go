// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"bytes"
	"strings"
	"testing"
	"time"

	amfctx "github.com/omec-project/amf/context"
)

// uePolicyCommandOf builds an n-octet MANAGE UE POLICY COMMAND under pti: the PTI, the message
// type, and a UE policy section management list (LV-E) filling the rest. Interior and trailing
// zero octets, the shapes a payload-mangling codec breaks.
func uePolicyCommandOf(pti uint8, n int) []byte {
	msg := make([]byte, n)
	msg[0], msg[1] = pti, uePolicyCommand
	listLen := n - 4
	msg[2], msg[3] = byte(listLen>>8), byte(listLen)
	for i := 4; i < n; i++ {
		msg[i] = byte(i * 37)
	}
	return msg
}

func uePolicyAnswer(pti, msgType uint8) []byte { return []byte{pti, msgType} }

// uePolicyRecords returns the uEPolicy of every AMFUEPolicyTransfer snd received, in order.
func uePolicyRecords(t *testing.T, snd *captureSender) [][]byte {
	t.Helper()

	var out [][]byte
	for _, rec := range decodeRecords(t, snd) {
		if rec.event == eventUEPolicyTransfer {
			out = append(out, rec.member(t, 6).Bytes)
		}
	}
	return out
}

// TestAUEPolicyCompleteReportsTheCommandItConfirms: TS 33.128 clause 6.2.2.2.12 triggers the
// record on the UE's MANAGE UE POLICY COMPLETE, and its uEPolicy is "Content of the N1 NAS
// message MANAGE UE POLICY COMMAND". One record, on the COMPLETE, carrying the COMMAND
// byte-identical.
func TestAUEPolicyCompleteReportsTheCommandItConfirms(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)
	ue := targetUE()

	command := uePolicyCommandOf(5, 16)
	NoteUEPolicyCommand(ue, command)
	if n := len(snd.pdus); n != 0 {
		t.Fatalf("the COMMAND produced %d record(s); the clause triggers on the COMPLETE alone", n)
	}

	ReportUEPolicyComplete(ue, uePolicyAnswer(5, uePolicyComplete))

	got := uePolicyRecords(t, snd)
	if len(got) != 1 {
		t.Fatalf("delivered %d AMFUEPolicyTransfer records for one completed procedure, want 1", len(got))
	}
	if !bytes.Equal(got[0], command) {
		t.Errorf("uEPolicy = % x, want the COMMAND the COMPLETE confirms % x", got[0], command)
	}
}

// TestAUEPolicyCompleteWithNoCommandReportsNothing: the record's uEPolicy is mandatory and is
// the COMMAND; the COMPLETE is not that content. A COMPLETE whose COMMAND this element did not
// hold produces nothing, rather than a record carrying the two-octet COMPLETE, which the
// encoder refuses — on every policy exchange — as a recordNotEncoded fault.
//
// Nothing delivered is not enough to show that: the refused record is not delivered either. So
// the assertion is also on the fault channel, which TestAShortUEPolicyCommandIsRefusedNotDelivered
// shows does carry recordNotEncoded in this harness.
func TestAUEPolicyCompleteWithNoCommandReportsNothing(t *testing.T) {
	admf := newADMFStub(t)
	snd := &captureSender{}
	activateIRIReporting(t, snd, admf.srv.URL)

	ReportUEPolicyComplete(targetUE(), uePolicyAnswer(5, uePolicyComplete))

	if n := len(snd.pdus); n != 0 {
		t.Errorf("a COMPLETE with no COMMAND held produced %d record(s)", n)
	}
	time.Sleep(time.Second)
	if got := strings.Join(admf.received(), "\n"); strings.Contains(got, "recordNotEncoded") {
		t.Errorf("a COMPLETE with no COMMAND held was encoded as a record and refused:\n%s", got)
	}
}

// TestAUEPolicyCommandAloneReportsNothing: a COMMAND the UE has not accepted is not the event
// the clause names.
func TestAUEPolicyCommandAloneReportsNothing(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)

	NoteUEPolicyCommand(targetUE(), uePolicyCommandOf(5, 16))

	if n := len(snd.pdus); n != 0 {
		t.Errorf("an unanswered COMMAND produced %d record(s)", n)
	}
}

// TestInterleavedUEPolicyProceduresEachReportTheirOwnCommand: the COMPLETE names its procedure
// by PTI, and two procedures may be open at once. Each COMPLETE carries its own COMMAND.
func TestInterleavedUEPolicyProceduresEachReportTheirOwnCommand(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)
	ue := targetUE()

	first, second := uePolicyCommandOf(1, 16), uePolicyCommandOf(2, 20)
	NoteUEPolicyCommand(ue, first)
	NoteUEPolicyCommand(ue, second)
	ReportUEPolicyComplete(ue, uePolicyAnswer(2, uePolicyComplete))
	ReportUEPolicyComplete(ue, uePolicyAnswer(1, uePolicyComplete))

	got := uePolicyRecords(t, snd)
	if len(got) != 2 || !bytes.Equal(got[0], second) || !bytes.Equal(got[1], first) {
		t.Errorf("records = % x, want the PTI 2 COMMAND then the PTI 1 COMMAND", got)
	}
}

// TestAUEPolicyProcedureIsReportedOnce: a T3501 retransmission repeats the COMMAND under its
// PTI, and a COMPLETE ends the procedure. One record either way.
func TestAUEPolicyProcedureIsReportedOnce(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)
	ue := targetUE()

	command := uePolicyCommandOf(7, 16)
	NoteUEPolicyCommand(ue, command)
	NoteUEPolicyCommand(ue, command)
	ReportUEPolicyComplete(ue, uePolicyAnswer(7, uePolicyComplete))
	ReportUEPolicyComplete(ue, uePolicyAnswer(7, uePolicyComplete))

	if got := uePolicyRecords(t, snd); len(got) != 1 {
		t.Errorf("delivered %d records for one procedure, want 1", len(got))
	}
}

// TestARejectedUEPolicyCommandReportsNothing: the clause names only the COMPLETE. A COMMAND
// REJECT ends the procedure, so a later COMPLETE reusing the PTI does not report it either.
func TestARejectedUEPolicyCommandReportsNothing(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)
	ue := targetUE()

	NoteUEPolicyCommand(ue, uePolicyCommandOf(3, 16))
	ReportUEPolicyComplete(ue, uePolicyAnswer(3, uePolicyCommandReject))
	ReportUEPolicyComplete(ue, uePolicyAnswer(3, uePolicyComplete))

	if n := len(snd.pdus); n != 0 {
		t.Errorf("a rejected COMMAND produced %d record(s)", n)
	}
}

// TestAnUntaskedUEHoldsNoUEPolicyCommand: a subscriber under no warrant costs nothing here.
func TestAnUntaskedUEHoldsNoUEPolicyCommand(t *testing.T) {
	activateIRI(t, &captureSender{}, "999999999999999")

	NoteUEPolicyCommand(targetUE(), uePolicyCommandOf(1, 16))

	if n := len(active.Load().policies.byUE); n != 0 {
		t.Errorf("an untasked UE's COMMAND was held: %d UE(s) held", n)
	}
}

// TestDeregisteringFromEveryAccessForgetsTheUEPolicyCommands: a UE registered on no access
// completes no procedure it had open, so what was held for it goes.
func TestDeregisteringFromEveryAccessForgetsTheUEPolicyCommands(t *testing.T) {
	snd := &captureSender{}
	activateIRI(t, snd, testTargetSUPI)
	ue := targetUE()

	NoteUEPolicyCommand(ue, uePolicyCommandOf(1, 16))
	ReportIdentifierDeassociation(ue)

	if n := len(active.Load().policies.byUE); n != 0 {
		t.Errorf("%d UE(s) still held after the UE left every access", n)
	}
}

// TestHeldUEPolicyCommandsAreBounded: per UE, the oldest gives way; in total, a UE beyond the
// bound is not held.
func TestHeldUEPolicyCommandsAreBounded(t *testing.T) {
	var p pendingPolicies
	ue := &amfctx.AmfUe{}

	for pti := uint8(1); pti <= maxPendingPerUE+1; pti++ {
		p.remember(ue, pti, uePolicyCommandOf(pti, 16))
	}
	if n := len(p.byUE[ue]); n != maxPendingPerUE {
		t.Errorf("one UE holds %d COMMANDs, want at most %d", n, maxPendingPerUE)
	}
	if p.take(ue, 1) != nil {
		t.Error("the oldest COMMAND survived the per-UE bound")
	}
	if p.take(ue, maxPendingPerUE+1) == nil {
		t.Error("the newest COMMAND was dropped instead of the oldest")
	}

	p = pendingPolicies{}
	for range maxPendingUEs {
		p.remember(&amfctx.AmfUe{}, 1, uePolicyCommandOf(1, 16))
	}
	late := &amfctx.AmfUe{}
	p.remember(late, 1, uePolicyCommandOf(1, 16))
	if _, held := p.byUE[late]; held || len(p.byUE) != maxPendingUEs {
		t.Errorf("%d UEs held, want at most %d", len(p.byUE), maxPendingUEs)
	}
}

// TestAShortUEPolicyCommandIsRefusedNotDelivered covers the one real conflict in the record's
// definition. TS 33.128 makes uEPolicy mandatory and defines `UEPolicy ::= OCTET STRING
// (SIZE(16..65540))`, which fits a COMMAND carrying the optional UE policy network classmark.
// A COMMAND with neither optional IE and a management list of 11–13 octets is 13–15 octets: the
// prose mandates the record and the schema forbids it. This project follows the schema and
// declares the contradiction (li/iri CONFORMANCE).
//
// What must not happen is that the gap is invisible. Relaxing the bound would not deliver the
// record — a mediation function validating against the published module discards it exactly
// as this encoder does — it would only move the discard to the far end, where this element
// cannot see it. So nothing is delivered, and the encoder's refusal is what reports it.
func TestAShortUEPolicyCommandIsRefusedNotDelivered(t *testing.T) {
	admf := newADMFStub(t)
	snd := &captureSender{}
	activateIRIReporting(t, snd, admf.srv.URL)
	ue := targetUE()

	NoteUEPolicyCommand(ue, uePolicyCommandOf(4, 13))
	ReportUEPolicyComplete(ue, uePolicyAnswer(4, uePolicyComplete))

	if n := len(snd.pdus); n != 0 {
		t.Errorf("delivered %d records for a COMMAND the definition forbids. A conformant "+
			"mediation function discards it, and this element would believe it had delivered", n)
	}
	if n := len(active.Load().policies.byUE); n != 0 {
		t.Errorf("the COMPLETE left %d UE(s) held: it was not matched to its COMMAND, so this "+
			"test is not exercising the encoder's refusal", n)
	}
	if got := awaitReport(t, admf, "recordNotEncoded"); !strings.Contains(got, "recordNotEncoded") {
		t.Errorf("the refused record was not reported against the warrant; the ADMF received:\n%s", got)
	}
}

// TestOnlyACommandIsHeld: the network also sends UE POLICY PROVISIONING REJECT downlink
// (TS 24.501 table D.6.1.1). Held as a COMMAND, a COMPLETE reusing its PTI would report it.
func TestOnlyACommandIsHeld(t *testing.T) {
	activateIRI(t, &captureSender{}, testTargetSUPI)

	const uePolicyProvisioningReject = 0x06
	NoteUEPolicyCommand(targetUE(), []byte{1, uePolicyProvisioningReject, 0x00})

	if n := len(active.Load().policies.byUE); n != 0 {
		t.Errorf("a downlink policy message other than a COMMAND was held: %d UE(s)", n)
	}
}
