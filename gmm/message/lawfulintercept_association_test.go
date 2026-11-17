// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import (
	"testing"

	"github.com/omec-project/amf/context"
	"github.com/omec-project/amf/factory"
	"github.com/omec-project/nas/v2/nasConvert"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
)

// TestTheIdentifierAssociationIsReportedOnEveryAccessPath asserts the association record at
// the seam both access paths cross.
//
// HandleInitialRegistration branches on access type: 3GPP calls SendRegistrationAccept, and
// non-3GPP calls SendInitialContextSetupRequest and then BuildRegistrationAccept *directly*,
// stashing the result in ue.RegistrationAcceptForNon3GPPAccess for the N3IWF's answer. A hook
// on the sender leaves a target registering over non-3GPP with its SUPI bound to a 5G-GUTI,
// carried to the UE, and reported nowhere — while the registration itself *is* reported,
// because ReportRegistration fires from the access-agnostic HandleRegistrationComplete. That
// makes the gap look like coverage from outside, and it is why this test is written against
// the association record specifically.
//
// The hook is on the builder, which both paths cross and where the 5G-GUTI IE is placed, so
// the seam and the fact the record reports coincide.
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

	// A mobility or periodic update reports an association only when its accept carries a
	// 5G-GUTI the UE did not register with: an update that presents the GUTI the UE keeps
	// binds nothing new, and one that presents another identity, or a GUTI the AMF has since
	// reallocated, does.
	for _, c := range []struct {
		name      string
		presented []uint8
		want      int
	}{
		{"presenting the GUTI it keeps", gutiOctets(heldGUTI), 0},
		{"presenting a GUTI the AMF reallocated", gutiOctets("20893cafe0000000002"), 1},
		{"presenting a SUCI", []uint8{nasMessage.MobileIdentity5GSTypeSuci, 0x02, 0xf8, 0x39}, 1},
	} {
		t.Run("mobility update "+c.name, func(t *testing.T) {
			reported = 0
			ue := registeringUE(t)
			ue.Guti = heldGUTI
			ue.RegistrationType5GS = nasMessage.RegistrationType5GSMobilityRegistrationUpdating
			ue.RegistrationRequest = &nasMessage.RegistrationRequest{}
			ue.RegistrationRequest.MobileIdentity5GS.SetLen(uint16(len(c.presented)))
			ue.RegistrationRequest.MobileIdentity5GS.SetMobileIdentity5GSContents(c.presented)

			if _, err := BuildRegistrationAccept(ue, models.ACCESSTYPE__3_GPP_ACCESS, nil, nil, nil, nil); err != nil {
				t.Fatalf("BuildRegistrationAccept: %v", err)
			}

			if reported != c.want {
				t.Errorf("reported the identifier association %d times, want %d", reported, c.want)
			}
		})
	}
}

// heldGUTI is a 5G-GUTI in the form AllocateGutiToUe composes: PLMN, AMF identifier, and an
// eight-digit 5G-TMSI.
const heldGUTI = "20893cafe0000000001"

func gutiOctets(guti string) []uint8 {
	nas := nasConvert.GutiToNas(guti)
	return nas.Octet[:]
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
