// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"sync"
	"testing"
	"time"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
)

// blockingSender holds each delivery until it is released, and is safe to read from
// another goroutine — which captureSender is not, and which matters now that the
// start-of-interception scan runs on one.
type blockingSender struct {
	release chan struct{}

	mu   sync.Mutex
	pdus []*x2x3.PDU
}

func (b *blockingSender) Send(p *x2x3.PDU) error {
	<-b.release

	b.mu.Lock()
	defer b.mu.Unlock()
	b.pdus = append(b.pdus, p)

	return nil
}

func (b *blockingSender) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.pdus)
}

// registeredUE puts a registered UE carrying supi into the AMF's pool.
func registeredUE(t *testing.T, supi string) {
	t.Helper()

	ue := &amfctx.AmfUe{Supi: "imsi-" + supi}
	ue.State = map[models.AccessType]*fsm.State{
		models.ACCESSTYPE__3_GPP_ACCESS: fsm.NewState(amfctx.Registered),
	}
	amfctx.AMF_Self().UePool.Store(supi, ue)
	t.Cleanup(func() { amfctx.AMF_Self().UePool.Delete(supi) })
}

// TestStartOfInterceptionScanIsOffTheX1Goroutine.
//
// Activating a warrant made the element walk every UE it holds, on the X1 request
// goroutine, before answering. So the time to acknowledge a tasking request grew with
// the registered-UE population: an element that answers more slowly the busier it is,
// which is observable to whoever is asking, and is the provisioning-latency form of
// the same rule that keeps delivery off the signalling path. The SMF's equivalent has
// always run its scan on a goroutine.
//
// Asserted by blocking delivery. If the scan and its delivery were still on the
// caller's goroutine, the call could not return until the sender was released — and
// the X1 response would have waited with it.
func TestStartOfInterceptionScanIsOffTheX1Goroutine(t *testing.T) {
	const supi = "262019876543210"

	release := make(chan struct{})
	snd := &blockingSender{release: release}

	task := types.InterceptTask{
		XID:      "aaaaaaaa-0000-0000-0000-000000000001",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: supi}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}
	st := store.New()
	if !st.Activate(task) {
		t.Fatal("activate")
	}
	s := &subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: "10.0.60.122:42069", iriCtx: iri.NewContext(),
		ids: x2x3.NewIdentity("amf-1", amfInterceptionPoint),
	}
	registeredUE(t, supi)

	returned := make(chan struct{})
	go func() {
		s.reportStartOfInterception(task, nil)
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("reportStartOfInterception did not return while delivery was blocked: " +
			"the UE-pool scan is still on the X1 request goroutine, so acknowledging a " +
			"warrant waits on every UE this element holds")
	}

	// And the work still happens — off the goroutine is not instead of.
	if n := snd.count(); n != 0 {
		t.Fatalf("%d records delivered before the sender was released", n)
	}
	close(release)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if snd.count() == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Errorf("delivered %d start-of-interception records for one targeted registered UE, want 1",
		snd.count())
}

// TestStartOfInterceptionTimestampIsTheActivation keeps the instant where it belongs
// now that the scan is handed off. The records report the *activation*, not when the
// scan happened to reach each UE, so the clock is read before the goroutine starts —
// a reading taken inside it would drift by however long the scan waited to be
// scheduled, and a mediation function cannot tell the two apart.
func TestStartOfInterceptionTimestampIsTheActivation(t *testing.T) {
	const supi = "262019876543211"

	release := make(chan struct{})
	close(release) // deliver immediately
	snd := &blockingSender{release: release}

	task := types.InterceptTask{
		XID:      "aaaaaaaa-0000-0000-0000-000000000002",
		Targets:  []types.TargetIdentifier{{Type: types.TargetSUPI, Value: supi}},
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}
	st := store.New()
	if !st.Activate(task) {
		t.Fatal("activate")
	}
	s := &subsystem{
		store: st, senderFor: func(string) sender { return snd },
		mdf2: "10.0.60.122:42069", iriCtx: iri.NewContext(),
		ids: x2x3.NewIdentity("amf-1", amfInterceptionPoint),
	}
	registeredUE(t, supi)

	before := time.Now()
	s.reportStartOfInterception(task, nil)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && snd.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	after := time.Now()

	if snd.count() != 1 {
		t.Fatalf("delivered %d records, want 1", snd.count())
	}

	snd.mu.Lock()
	attrs := snd.pdus[0].Attributes
	snd.mu.Unlock()

	stamp, ok := timestampOf(attrs)
	if !ok {
		t.Fatal("the record carries no timestamp attribute")
	}
	if stamp.Before(before.Add(-time.Second)) || stamp.After(after) {
		t.Errorf("record timestamp %s is outside the activation window [%s, %s]", stamp, before, after)
	}
}

// timestampOf digs the clause 5.3.10 Timestamp out of a PDU's conditional
// attributes: two 32-bit unsigned integers, seconds then nanoseconds.
func timestampOf(attrs []x2x3.TLV) (time.Time, bool) {
	for _, a := range attrs {
		if a.Type == 9 && len(a.Value) == 8 {
			secs := uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3])
			nsec := uint32(a.Value[4])<<24 | uint32(a.Value[5])<<16 | uint32(a.Value[6])<<8 | uint32(a.Value[7])

			return time.Unix(int64(secs), int64(nsec)), true
		}
	}

	return time.Time{}, false
}
