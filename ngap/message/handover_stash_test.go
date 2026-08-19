// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"bytes"
	"testing"

	"github.com/omec-project/amf/logger"
	"github.com/omec-project/ngap/v2/ngapType"
	"github.com/omec-project/openapi/v2/models"
)

// TestADuplicateHandoverRequiredLeavesTheLiveHandoversStashIntact is the record-integrity
// property behind the AMFRANHandoverRequest xIRI.
//
// TS 33.128 puts that record on the HANDOVER REQUEST ACKNOWLEDGE, and the two values it
// needs — the cause and the source-to-target container — exist only on the way in, so they
// have to be stashed. Stashed by the *caller*, they were stashed before this function had
// decided whether to send: five guards return without sending, and one of them is "Handover
// Required Duplicated". So a duplicate HANDOVER REQUIRED overwrote the live handover's stash
// and sent nothing, and the first handover's acknowledgement was then reported with the
// rejected request's cause and container — a record describing a handover that never
// happened, attributed to one that did, with nothing in either stream to show it.
//
// Committed inside SendHandoverRequest, past the guards, the stash and the request carry the
// same values by construction: a request that is not sent replaces nothing.
func TestADuplicateHandoverRequiredLeavesTheLiveHandoversStashIntact(t *testing.T) {
	sourceUe := newRanUeForAllowedNSSAITest(models.ACCESSTYPE__3_GPP_ACCESS)
	// The fixture builds the RanUe as a literal, so it has no logger; every path below logs.
	sourceUe.Log = logger.NgapLog
	sourceUe.Ran.Log = logger.NgapLog

	live := &ngapType.Cause{
		Present:      ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason},
	}
	liveContainer := []byte{0x01, 0x02, 0x03, 0x04}

	// The live handover: sent, so its values are what the acknowledgement must report.
	SendHandoverRequest(sourceUe, sourceUe.Ran, *live,
		ngapType.PDUSessionResourceSetupListHOReq{
			List: []ngapType.PDUSessionResourceSetupItemHOReq{{}},
		},
		ngapType.SourceToTargetTransparentContainer{Value: liveContainer}, false)

	if sourceUe.HandOverCause == nil {
		t.Fatal("SendHandoverRequest stashed nothing for a request it sent: the values the " +
			"AMFRANHandoverRequest xIRI needs are committed here, past the guards, precisely so " +
			"a request that is not sent cannot replace a live handover's — a caller that stashes " +
			"before the call has already overwritten it by the time this function decides")
	}
	if sourceUe.TargetUe == nil {
		t.Fatal("the live handover did not reach the target-UE attachment, so the duplicate " +
			"guard below is not the one that will fire")
	}

	// The duplicate: `sourceUe.TargetUe != nil` now, so this returns on the
	// "Handover Required Duplicated" guard without sending anything.
	rejected := &ngapType.Cause{
		Present: ngapType.CausePresentMisc,
		Misc:    &ngapType.CauseMisc{Value: ngapType.CauseMiscPresentUnspecified},
	}
	SendHandoverRequest(sourceUe, sourceUe.Ran, *rejected,
		ngapType.PDUSessionResourceSetupListHOReq{
			List: []ngapType.PDUSessionResourceSetupItemHOReq{{}},
		},
		ngapType.SourceToTargetTransparentContainer{Value: []byte{0xAA, 0xBB}}, false)

	if sourceUe.HandOverCause.Present != live.Present {
		t.Errorf("the stashed cause is the rejected request's (present %d), want the live "+
			"handover's (%d): the first handover's acknowledgement now reports a cause from a "+
			"request that was never sent", sourceUe.HandOverCause.Present, live.Present)
	}
	if !bytes.Equal(sourceUe.HandOverSourceToTarget, liveContainer) {
		t.Errorf("the stashed container is %v, want the live handover's %v",
			sourceUe.HandOverSourceToTarget, liveContainer)
	}
}
