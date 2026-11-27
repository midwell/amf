// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
	"github.com/omec-project/util/li/iri"
	"github.com/omec-project/util/li/store"
	"github.com/omec-project/util/li/types"
	"github.com/omec-project/util/li/x2x3"
)

// TestAnAbortedReRegistrationReportsTheDeregistration: a UE registered on an access that starts
// a registration procedure there and fails it ends deregistered. TS 33.128 clause 6.2.2.2.3
// reports that as an AMFDeregistration, and clause 6.2.2.2.7 the end of the identifier binding
// when no access remains. A procedure that began deregistered reports nothing, and each
// procedure reports once.
func TestAnAbortedReRegistrationReportsTheDeregistration(t *testing.T) {
	const (
		eventDeregistration = 2
		eventDeassociation  = 186
	)
	for _, c := range []struct {
		name           string
		fromRegistered bool
		otherState     fsm.StateType
		removed        bool
		wantEvents     []int
		wantAccess     iri.AccessType
	}{
		{"began deregistered", false, amfctx.Deregistered, false, nil, 0},
		{"no other access", true, amfctx.Deregistered, false, []int{eventDeregistration, eventDeassociation}, iri.AccessThreeGPP},
		{"other access registered", true, amfctx.Registered, false, []int{eventDeregistration}, iri.AccessThreeGPP},
		{"context removed with the other access", true, amfctx.Registered, true, []int{eventDeregistration, eventDeassociation}, iri.AccessBoth},
	} {
		t.Run(c.name, func(t *testing.T) {
			snd := &captureSender{}
			st := store.New()
			st.Activate(types.InterceptTask{
				XID:         testSubstitutionXID,
				Targets:     []types.TargetIdentifier{{Type: types.TargetSUPI, Value: testTargetSUPI}},
				Products:    []types.ProductType{types.ProductIRI},
				RecordScope: types.RecordScopeAll,
			})
			active.Store(&subsystem{
				ids:   x2x3.NewIdentity(testNEID, amfInterceptionPoint),
				store: st, senderFor: func(string) sender { return snd }, mdf2: testAgencyAddr,
			})
			t.Cleanup(func() { active.Store(nil) })

			ue := targetUE()
			ue.State = map[models.AccessType]*fsm.State{
				models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(amfctx.ContextSetup),
				models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(c.otherState),
			}
			ue.SetRegisteredAtProcedureStart(models.ACCESSTYPE__3_GPP_ACCESS, c.fromRegistered)

			ReportAbortedRegistration(ue, models.ACCESSTYPE__3_GPP_ACCESS, c.removed)
			ReportAbortedRegistration(ue, models.ACCESSTYPE__3_GPP_ACCESS, c.removed)

			records := decodeRecords(t, snd)
			if len(records) != len(c.wantEvents) {
				t.Fatalf("delivered %d records, want %d", len(records), len(c.wantEvents))
			}
			for i, want := range c.wantEvents {
				if records[i].event != want {
					t.Errorf("record %d is XIRIEvent [%d], want [%d]", i, records[i].event, want)
				}
			}
			if len(records) == 0 {
				return
			}
			if got := integer(t, records[0].member(t, 1)); got != int64(iri.DirNetworkInitiated) {
				t.Errorf("deregistrationDirection = %d, want network-initiated", got)
			}
			if got := integer(t, records[0].member(t, 2)); got != int64(c.wantAccess) {
				t.Errorf("accessType = %d, want %d", got, c.wantAccess)
			}
		})
	}
}
