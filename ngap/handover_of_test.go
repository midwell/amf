// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package ngap

import (
	"testing"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/ngap/v2/ngapType"
)

// TestAHandoverRecordKnowsWhetherHandoverRequiredWasCarried: the AMFRANHandoverRequest record
// needs HANDOVER REQUIRED's source-to-target container, carried forward in the RanUe's stash.
// No stash — the REQUIRED was never seen, or its state was already cleared — is a record that
// cannot be completed and is reported as not produced; a stash is the container to report.
// The acknowledge's own target-to-source container may be empty and is carried as it came.
func TestAHandoverRecordKnowsWhetherHandoverRequiredWasCarried(t *testing.T) {
	list := ngapType.PDUSessionResourceHandoverList{}

	stashed := &context.RanUe{HandOverSourceToTarget: []byte{0x01, 0x02}}
	if h := handoverOf(stashed, []byte{}, list); !h.HasSourceToTarget {
		t.Error("a stashed source-to-target container was not marked carried, so the record " +
			"would be reported as not produced although everything it needs is held")
	} else if h.TargetToSource == nil || len(h.TargetToSource) != 0 {
		t.Errorf("the acknowledge's empty container became % x (nil=%v), want it as sent",
			h.TargetToSource, h.TargetToSource == nil)
	}

	cleared := &context.RanUe{}
	if h := handoverOf(cleared, []byte{0x03}, list); h.HasSourceToTarget {
		t.Error("no stash was marked carried, so the record would be emitted with a missing " +
			"mandatory container")
	}
}
