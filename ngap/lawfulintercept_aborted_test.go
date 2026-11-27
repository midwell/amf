// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package ngap

import (
	ctxt "context"
	"testing"
	"time"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
)

// An INITIAL CONTEXT SETUP FAILURE while T3550 runs ends the registration procedure with the
// access Deregistered, so the procedure is handed to lawfulintercept.ReportAbortedRegistration,
// which consumes the record of whether it began from Registered.
func TestAnInitialContextSetupFailureAccountsForTheRegistrationItEnds(t *testing.T) {
	ran, ranUe, amfUe := newReleasingUe(t, "imsi-208930100009986", context.UeContextN2NormalRelease, 986)
	amfUe.State[models.ACCESSTYPE__3_GPP_ACCESS] = fsm.NewState(context.ContextSetup)
	amfUe.T3550 = context.NewTimer(time.Hour, 0, func(int32) {}, func() {})
	amfUe.SetRegisteredAtProcedureStart(models.ACCESSTYPE__3_GPP_ACCESS, true)

	HandleInitialContextSetupFailure(ctxt.Background(), ran, &ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentUnsuccessfulOutcome,
		UnsuccessfulOutcome: &ngapType.UnsuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialContextSetup},
			Value: ngapType.UnsuccessfulOutcomeValue{
				Present: ngapType.UnsuccessfulOutcomePresentInitialContextSetup,
				InitialContextSetup: &ngapType.InitialContextSetupFailure{
					ProtocolIEs: ngapType.ProtocolIEContainerInitialContextSetupFailureIEs{
						List: []ngapType.InitialContextSetupFailureIEs{{
							Id: ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
							Value: ngapType.InitialContextSetupFailureIEsValue{
								Present:     ngapType.InitialContextSetupFailureIEsPresentRANUENGAPID,
								RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
							},
						}},
					},
				},
			},
		},
	})

	if amfUe.RegisteredAtProcedureStart(models.ACCESSTYPE__3_GPP_ACCESS) {
		t.Error("the failure left the registration it ends unaccounted for")
	}
}
