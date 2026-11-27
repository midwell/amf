// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"testing"
	"time"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
	"go.uber.org/zap"
)

// TestT3550RunningOutReportsOnlyAProcedureStillWaiting: when the UE never answers the
// REGISTRATION ACCEPT, T3550's last expiry sets the access 5GMM-REGISTERED (TS 24.501 clause
// 5.5.1.2.8 case c), which is the trigger of TS 33.128 clause 6.2.2.2.2, so the registration is
// reported there, once. Only while that procedure is still waiting: a failure that dropped the
// access to Deregistered, a REGISTRATION COMPLETE, or a later accept with its own T3550 has
// ended or replaced it, and a record then would report a registration that was torn down.
//
// The expiry's serialized work is invoked directly: the real timer writes on its own goroutine,
// which a test driving it would race.
func TestT3550RunningOutReportsOnlyAProcedureStillWaiting(t *testing.T) {
	const access = models.ACCESSTYPE__3_GPP_ACCESS
	reported := 0
	original := liReportRegistration
	liReportRegistration = func(*context.AmfUe, models.AccessType) { reported++ }
	t.Cleanup(func() { liReportRegistration = original })

	this := context.NewTimer(time.Hour, 0, func(int32) {}, func() {})
	other := context.NewTimer(time.Hour, 0, func(int32) {}, func() {})
	t.Cleanup(func() { this.Stop(); other.Stop() })

	for _, c := range []struct {
		name   string
		state  fsm.StateType
		t3550  *context.Timer
		report bool
	}{
		{"still waiting for the answer", context.ContextSetup, this, true},
		{"the RAN leg was released meanwhile", context.ContextSetup, nil, true},
		{"a context setup failure ended the procedure", context.Deregistered, nil, false},
		{"REGISTRATION COMPLETE arrived", context.Registered, nil, false},
		{"a later accept runs its own T3550", context.ContextSetup, other, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			reported = 0
			ue := &context.AmfUe{
				GmmLog: zap.NewNop().Sugar(),
				State:  map[models.AccessType]*fsm.State{access: fsm.NewState(c.state)},
				OnGoing: map[models.AccessType]*context.OnGoingProcedureWithPrio{
					access: {Procedure: context.OnGoingProcedureRegistration},
				},
				T3550: c.t3550,
			}

			registrationAcceptUnanswered(ue, access, this)

			if want := map[bool]int{true: 1, false: 0}[c.report]; reported != want {
				t.Errorf("reported the registration %d times, want %d", reported, want)
			}
			if registered := ue.State[access].Is(context.Registered); c.report && !registered {
				t.Error("the access was not set Registered")
			} else if !c.report && c.state != context.Registered && registered {
				t.Errorf("the access went from %s to Registered", c.state)
			}
		})
	}
}

// The expiry reaches that check: SendRegistrationAccept's T3550 hands its last expiry to it.
func TestT3550RunningOutGoesThroughTheCheck(t *testing.T) {
	if got := count(callsIn(t, "SendRegistrationAccept"), "registrationAcceptUnanswered"); got != 1 {
		t.Errorf("SendRegistrationAccept hands T3550's expiry to registrationAcceptUnanswered %d times, want 1", got)
	}
	if got := count(callsIn(t, "SendRegistrationAccept"), "liReportRegistration"); got != 0 {
		t.Errorf("SendRegistrationAccept reports the registration itself %d times, want 0", got)
	}
}
