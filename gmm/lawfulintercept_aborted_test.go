// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package gmm

import (
	ctxt "context"
	"testing"
	"time"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
	"go.uber.org/zap"
)

func procedureUE(state fsm.StateType) *context.AmfUe {
	return &context.AmfUe{
		GmmLog: zap.NewNop().Sugar(),
		RanUe:  map[models.AccessType]*context.RanUe{},
		State: map[models.AccessType]*fsm.State{
			models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(state),
			models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(context.Deregistered),
		},
	}
}

// TestARegistrationProcedureRecordsWhereItBegan: every registration procedure starts with
// StartAuthEvent, from Registered or from Deregistered, and the UE records which, so a
// procedure that fails knows whether it ended a registration.
func TestARegistrationProcedureRecordsWhereItBegan(t *testing.T) {
	const access = models.ACCESSTYPE__3_GPP_ACCESS
	for _, c := range []struct {
		from     fsm.StateType
		callback func(ctxt.Context, *fsm.State, fsm.EventType, fsm.ArgsType)
		want     bool
	}{
		{context.Registered, Registered, true},
		{context.Deregistered, DeRegistered, false},
	} {
		ue := procedureUE(c.from)
		ue.SetRegisteredAtProcedureStart(access, !c.want)
		c.callback(ctxt.Background(), ue.State[access], StartAuthEvent,
			fsm.ArgsType{ArgAmfUe: ue, ArgAccessType: access})
		if got := ue.RegisteredAtProcedureStart(access); got != c.want {
			t.Errorf("a procedure starting from %s records %v, want %v", c.from, got, c.want)
		}
	}
}

// TestEveryFailedProcedureAccountsForTheRegistrationItEnds: each event that drops a
// registration procedure to Deregistered hands the procedure to
// lawfulintercept.ReportAbortedRegistration, which consumes the record of where it began.
func TestEveryFailedProcedureAccountsForTheRegistrationItEnds(t *testing.T) {
	disableKafkaForRelayTest(t)
	const access = models.ACCESSTYPE__3_GPP_ACCESS
	for _, c := range []struct {
		state    fsm.StateType
		callback func(ctxt.Context, *fsm.State, fsm.EventType, fsm.ArgsType)
		event    fsm.EventType
	}{
		{context.Authentication, Authentication, AuthFailEvent},
		{context.Authentication, Authentication, AuthErrorEvent},
		{context.SecurityMode, SecurityMode, SecurityModeFailEvent},
		{context.SecurityMode, SecurityMode, SecurityModeAbortEvent},
		{context.ContextSetup, ContextSetup, ContextSetupFailEvent},
	} {
		ue := procedureUE(c.state)
		ue.T3560 = context.NewTimer(time.Hour, 0, func(int32) {}, func() {})
		ue.SetRegisteredAtProcedureStart(access, true)
		c.callback(ctxt.Background(), ue.State[access], c.event,
			fsm.ArgsType{ArgAmfUe: ue, ArgAccessType: access})
		if ue.RegisteredAtProcedureStart(access) {
			t.Errorf("%s in %s left the registration it ends unaccounted for", c.event, c.state)
		}
		if ue.T3560 != nil {
			ue.T3560.Stop()
		}
	}
}
