// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"testing"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/amf/factory"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
)

// TestTheIdentifierAssociationIsReportedOnEveryAccessPath is the record that was missing
// over non-3GPP access, and it is asserted at the seam both access paths cross.
//
// ReportIdentifierAssociation used to hang off SendRegistrationAccept. HandleInitialRegistration
// branches on access type: 3GPP calls that sender, and non-3GPP calls
// SendInitialContextSetupRequest and then BuildRegistrationAccept *directly*, stashing
// the result in ue.RegistrationAcceptForNon3GPPAccess for the N3IWF's answer. So a target
// registering over non-3GPP had its SUPI bound to a 5G-GUTI, carried to the UE, and
// reported nowhere — while the registration itself *was* reported, because
// ReportRegistration fires from the access-agnostic HandleRegistrationComplete. That is
// exactly what made the gap look like coverage from outside, and it is why this test is
// written against the association record specifically.
//
// The hook now lives on the builder, which both paths cross and where the 5G-GUTI IE is
// placed, so the seam and the fact the record reports coincide.
func TestTheIdentifierAssociationIsReportedOnEveryAccessPath(t *testing.T) {
	var reported int
	original := liReportIdentifierAssociation
	liReportIdentifierAssociation = func(*context.AmfUe) { reported++ }
	t.Cleanup(func() { liReportIdentifierAssociation = original })

	for _, access := range []models.AccessType{
		models.ACCESSTYPE__3_GPP_ACCESS,
		models.ACCESSTYPE_NON_3_GPP_ACCESS,
	} {
		t.Run(string(access), func(t *testing.T) {
			reported = 0
			ue := registeringUE(t)
			ue.RegistrationType5GS = nasMessage.RegistrationType5GSInitialRegistration

			//nolint:errcheck // the built message is not what this asserts on
			_, _ = BuildRegistrationAccept(ue, access, nil, nil, nil, nil)

			if reported != 1 {
				t.Errorf("an initial registration over %s reported the identifier association %d times, want 1: "+
					"the AMF bound this target's SUPI to a 5G-GUTI, carried it to the UE, and said nothing",
					access, reported)
			}
		})
	}

	// The gate is what keeps this from becoming noise, and what lets the builder carry
	// the hook safely: the other callers are all mobility and periodic updates, which
	// re-send the same GUTI without reassigning it.
	t.Run("mobility update reports nothing", func(t *testing.T) {
		reported = 0
		ue := registeringUE(t)
		ue.RegistrationType5GS = nasMessage.RegistrationType5GSMobilityRegistrationUpdating

		//nolint:errcheck // as above
		_, _ = BuildRegistrationAccept(ue, models.ACCESSTYPE__3_GPP_ACCESS, nil, nil, nil, nil)

		if reported != 0 {
			t.Errorf("a mobility registration update reported an identifier association %d times, want 0",
				reported)
		}
	})
}

// registeringUE is the minimum a Registration Accept can be built for: a GUTI, a PLMN,
// both access states (the registration result reads them), and a configuration for the
// network-feature-support IE. The same shape TestRegistrationAcceptCarriesGUTIWheneverTheUEHasOne
// uses, for the same reason — these tests do not stand up an AMF.
func registeringUE(t *testing.T) *context.AmfUe {
	t.Helper()

	ue := &context.AmfUe{Guti: "20893cafe0000001"}
	ue.PlmnId = models.PlmnId{Mcc: "208", Mnc: "93"}
	ue.State = map[models.AccessType]*fsm.State{
		models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(context.Deregistered),
		models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(context.Deregistered),
	}

	if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
		t.Cleanup(func() { factory.AmfConfig.Configuration = nil })
	}

	return ue
}
