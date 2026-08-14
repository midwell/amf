// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x2x3"
)

// attrsOf indexes a PDU's conditional attributes by type, keeping every occurrence:
// the two target identifier attributes are the ones clause 5.3.1 permits more than
// one of, and collapsing them would hide exactly what these tests are about.
func attrsOf(pdu *x2x3.PDU) map[uint16][]string {
	out := make(map[uint16][]string, len(pdu.Attributes))
	for _, a := range pdu.Attributes {
		out[a.Type] = append(out[a.Type], string(a.Value))
	}

	return out
}

func seqOf(t *testing.T, pdu *x2x3.PDU) uint32 {
	t.Helper()
	for _, a := range pdu.Attributes {
		if a.Type == x2x3.AttrSequenceNumber {
			return binary.BigEndian.Uint32(a.Value)
		}
	}
	t.Fatal("PDU carries no sequence number")

	return 0
}

// activateIRIWithTargets installs a warrant naming exactly the identifiers given,
// with as many delivery destinations as addrs names, delivering everything to snd.
func activateIRIWithTargets(t *testing.T, snd sender, targets []types.TargetIdentifier, addrs ...string) {
	t.Helper()
	task := types.InterceptTask{
		XID:      "aaaaaaaa-0000-0000-0000-000000000001",
		Targets:  targets,
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}
	for _, addr := range addrs {
		task.Deliveries = append(task.Deliveries, types.DeliveryEndpoint{Type: types.DeliveryX2, Address: addr})
	}
	st := store.New()
	if !st.Activate(task) {
		t.Fatal("activate")
	}
	active.Store(&subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: "10.0.60.122:42069", iriCtx: iri.NewContext(),
		ids: x2x3.NewIdentity("amf-1", amfInterceptionPoint),
	})
	t.Cleanup(func() { active.Store(nil) })
}

// TestXIRICarriesTheSixRequiredAttributes is TS 33.128 table 5.3.2-2 on the
// signalling path. Every xIRI this element has ever delivered carried none of these:
// the payload was conformant and the header it travelled in was not.
func TestXIRICarriesTheSixRequiredAttributes(t *testing.T) {
	snd := &captureSender{}
	activateIRIWithTargets(t, snd, []types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}})

	ReportRegistration(targetUE())
	if len(snd.pdus) != 1 {
		t.Fatalf("delivered %d records, want 1", len(snd.pdus))
	}
	attrs := attrsOf(snd.pdus[0])

	// The NFID is the identifier this element asserts on X1, so the mediation function
	// and the ADMF name the same element.
	if got := attrs[x2x3.AttrNFID]; len(got) != 1 || got[0] != "amf-1" {
		t.Errorf("NFID = %q, want the configured network element identifier", got)
	}
	if got := attrs[x2x3.AttrIPID]; len(got) != 1 || got[0] != amfInterceptionPoint {
		t.Errorf("IPID = %q, want %q", got, amfInterceptionPoint)
	}
	if got := attrs[x2x3.AttrTimestamp]; len(got) != 1 || len(got[0]) != 8 {
		t.Errorf("timestamp = %q, want one 8-octet timespec", got)
	}
	if got := attrs[x2x3.AttrSequenceNumber]; len(got) != 1 {
		t.Errorf("sequence number occurrences = %d, want 1", len(got))
	}

	// The matched identity is the one the task named and the UE presents; the other
	// identities are the rest of *this subject's*, one attribute each.
	if got := attrs[x2x3.AttrMatchedTargetIdentifier]; len(got) != 1 || got[0] != "<supiimsi>"+testTargetSUPI+"</supiimsi>" {
		t.Errorf("matched target identifier = %q, want the SUPI the task named", got)
	}
	wantOther := map[string]bool{
		"<peiImei>3534250000000151</peiImei>":    true,
		"<gpsiMsisdn>4915123456789</gpsiMsisdn>": true,
	}
	other := attrs[x2x3.AttrOtherTargetIdentifier]
	if len(other) != len(wantOther) {
		t.Errorf("other target identifiers = %q, want %d of them", other, len(wantOther))
	}
	for _, got := range other {
		if !wantOther[got] {
			t.Errorf("unexpected other target identifier %q", got)
		}
	}
}

// TestEveryMatchedIdentityIsReported: where a task names two identities the subject
// presents, both matched. Reporting one and calling it the match is a claim the
// element cannot support, and clause 5.3.18 permits multiple occurrences so that it
// need not make one.
func TestEveryMatchedIdentityIsReported(t *testing.T) {
	snd := &captureSender{}
	activateIRIWithTargets(t, snd, []types.TargetIdentifier{
		{Type: types.TargetSUPI, Value: testTargetSUPI},
		{Type: types.TargetGPSI, Value: "4915123456789"},
	})

	ReportRegistration(targetUE())
	if len(snd.pdus) != 1 {
		t.Fatalf("delivered %d records, want 1", len(snd.pdus))
	}
	attrs := attrsOf(snd.pdus[0])

	if got := len(attrs[x2x3.AttrMatchedTargetIdentifier]); got != 2 {
		t.Errorf("matched identities = %d (%q), want both the task named", got, attrs[x2x3.AttrMatchedTargetIdentifier])
	}
	if got := attrs[x2x3.AttrOtherTargetIdentifier]; len(got) != 1 || got[0] != "<peiImei>3534250000000151</peiImei>" {
		t.Errorf("other identities = %q, want only the PEI", got)
	}
}

// TestOnlyTheSubjectsIdentitiesAreReported guards the reading of "all other target
// identities present at the NF" that would put every subscriber the AMF holds into
// every header. That is not a cost problem, it is a disclosure: an agency holding a
// warrant for one subject would receive the identities of others.
func TestOnlyTheSubjectsIdentitiesAreReported(t *testing.T) {
	snd := &captureSender{}
	activateIRIWithTargets(t, snd, []types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}})

	// A second, untasked subscriber known to this AMF at the same time.
	other := &amfctx.AmfUe{Supi: "imsi-262010000000999", Pei: "imeisv-3534250000000999", Gpsi: "msisdn-4915100000999"}
	ReportRegistration(other)
	ReportRegistration(targetUE())

	if len(snd.pdus) != 1 {
		t.Fatalf("delivered %d records, want 1 — only the tasked subject", len(snd.pdus))
	}
	attrs := attrsOf(snd.pdus[0])
	reported := append(attrs[x2x3.AttrMatchedTargetIdentifier], attrs[x2x3.AttrOtherTargetIdentifier]...)
	for _, frag := range reported {
		for _, leaked := range []string{"262010000000999", "3534250000000999", "4915100000999"} {
			if strings.Contains(frag, leaked) {
				t.Errorf("header carries %q, which belongs to a subscriber this warrant does not name", frag)
			}
		}
	}
}

// TestSequenceNumbersAreOnePerRecordNotPerDestination: the number belongs to the
// (XID, Correlation ID) context, so a record delivered to two of a task's
// destinations carries one number at both. A counter per connection would give the
// same record two different numbers and a mediation function no way to tell that they
// are one record.
func TestSequenceNumbersAreOnePerRecordNotPerDestination(t *testing.T) {
	snd := &captureSender{}
	activateIRIWithTargets(t, snd,
		[]types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}},
		"10.0.60.122:42069", "10.0.60.123:42069")

	ReportRegistration(targetUE())
	if len(snd.pdus) != 2 {
		t.Fatalf("delivered %d copies, want one per destination", len(snd.pdus))
	}
	if a, b := seqOf(t, snd.pdus[0]), seqOf(t, snd.pdus[1]); a != b {
		t.Errorf("the same record was numbered %d and %d", a, b)
	}

	// The next record in the same context is the next number, once — not once per
	// destination.
	ReportRegistration(targetUE())
	if got := seqOf(t, snd.pdus[2]); got != 1 {
		t.Errorf("second record numbered %d, want 1: the numbering counted destinations", got)
	}
}

// droppingSender delivers every PDU but the second, standing in for the bounded
// delivery queue discarding product while the MDF is slower than the offered rate.
type droppingSender struct {
	seen   int
	kept   []*x2x3.PDU
	dropAt int
}

func (d *droppingSender) Send(pdu *x2x3.PDU) error {
	d.seen++
	if d.seen == d.dropAt {
		return nil // dropped, exactly as a full queue drops it
	}
	d.kept = append(d.kept, pdu)

	return nil
}

// TestDroppedProductLeavesAGap: the number is taken where the record is built, not
// where it is written, so product lost to a full delivery queue shows up at the
// mediation function as a missing number. Renumbering to close the gap would make
// loss invisible — and loss that cannot be seen cannot be distinguished from a
// subject who did nothing.
func TestDroppedProductLeavesAGap(t *testing.T) {
	snd := &droppingSender{dropAt: 2}
	activateIRIWithTargets(t, snd, []types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}})

	for range 3 {
		ReportRegistration(targetUE())
	}

	if len(snd.kept) != 2 {
		t.Fatalf("delivered %d records, want 2 of 3", len(snd.kept))
	}
	if got := seqOf(t, snd.kept[0]); got != 0 {
		t.Errorf("first delivered record numbered %d, want 0", got)
	}
	if got := seqOf(t, snd.kept[1]); got != 2 {
		t.Errorf("record after the dropped one numbered %d, want 2 — the gap was closed over", got)
	}
}

// TestInitRefusesWithoutAnElementIdentifier is design D9: an element that cannot say
// which network function produced a record does not deliver one. The refusal is a
// returned error rather than a fatal start-up, because the AMF must carry on serving
// traffic — a network function that crash-loops over its LI configuration announces to
// every operator with log access that it is LI-provisioned.
func TestInitRefusesWithoutAnElementIdentifier(t *testing.T) {
	if err := Init(Config{X1Listen: "127.0.0.1:0"}); !errors.Is(err, errNoElementIdentifier) {
		t.Errorf("Init without a network element identifier returned %v, want errNoElementIdentifier", err)
	}
	if active.Load() != nil {
		t.Error("interception is running after a refused initialisation")
	}
}

// TestDeactivationForgetsTheNumbering is the leak guard for the sequence numbering.
// The state is per (XID, Correlation ID) context, so a warrant that outlives many
// sessions would otherwise leave one entry behind for each of them, for the life of
// the process. It is dropped through the X1 deactivation hook, so this drives it the
// way an ADMF does rather than by calling the hook directly.
func TestDeactivationForgetsTheNumbering(t *testing.T) {
	const xid, admf = "11111111-1111-4111-8111-111111111111", "admf-1"
	snd := &captureSender{}
	st := store.New()
	st.Activate(types.InterceptTask{
		XID:      xid,
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	})
	sub := &subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: "10.0.60.122:42069", iriCtx: iri.NewContext(),
		neID: "amf-1", ids: x2x3.NewIdentity("amf-1", amfInterceptionPoint),
	}
	srv := newX1Server(st, Config{NEID: "amf-1", AdmfID: admf}, sub)
	active.Store(sub)
	t.Cleanup(func() { active.Store(nil) })

	ReportRegistration(targetUE())
	if len(snd.pdus) != 1 || sub.ids.Contexts() != 1 {
		t.Fatalf("delivered %d records over %d contexts, want 1 and 1", len(snd.pdus), sub.ids.Contexts())
	}

	resp, err := srv.Process(bulkRequest("DeactivateAllTasksRequest", admf, "amf-1"), admfPeerCert(t, admf))
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Messages[0].ErrorInformation != nil {
		t.Fatalf("deactivation refused: %s", resp.Messages[0].ErrorInformation.ErrorDescription)
	}

	if n := sub.ids.Contexts(); n != 0 {
		t.Errorf("%d numbering contexts survive the tasking that created them", n)
	}
}

// TestTheTimestampIsTheEventsNotThePDUs is the property the whole timestamp
// decision rests on: what reaches the wire is the instant the caller observed the
// event, not the instant the PDU was assembled. Those differ whenever a record is
// built after the fact — a start-of-interception record for a UE that registered
// earlier, or several records built in a loop from one X1 activation — and a
// mediation function has no way to tell which one it was handed.
func TestTheTimestampIsTheEventsNotThePDUs(t *testing.T) {
	snd := &captureSender{}
	activateIRIWithTargets(t, snd, []types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}})
	sub := active.Load()

	happened := time.Date(2026, 8, 14, 6, 28, 15, 322_190_000, time.UTC)
	id := targetUE().IdentitySnapshot()
	sub.deliverIRI(sub.matchingTasks(id), targetsOf(id), happened, amfRegistration(id))
	sub.deliverIRI(sub.matchingTasks(id), targetsOf(id), happened, amfRegistration(id))

	if len(snd.pdus) != 2 {
		t.Fatalf("delivered %d records, want 2", len(snd.pdus))
	}
	for i, pdu := range snd.pdus {
		var got []byte
		for _, a := range pdu.Attributes {
			if a.Type == x2x3.AttrTimestamp {
				got = a.Value
			}
		}
		if len(got) != 8 {
			t.Fatalf("record %d carries no timestamp", i)
		}
		secs := binary.BigEndian.Uint32(got[0:4])
		nanos := binary.BigEndian.Uint32(got[4:8])
		if int64(secs) != happened.Unix() || int64(nanos) != int64(happened.Nanosecond()) {
			t.Errorf("record %d timestamped %d.%09d, want the event's %d.%09d — the clock was read where the PDU was built",
				i, secs, nanos, happened.Unix(), happened.Nanosecond())
		}
	}
}
