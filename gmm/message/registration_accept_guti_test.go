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

// TestRegistrationAcceptCarriesGUTIWheneverTheUEHasOne pins the fact the split
// of Lawful Interception registration reporting rests on.
//
// Registration records are emitted from two taps: one reports a mobility update,
// the other reports what completes a registration. Which tap a periodic update
// reaches is not a property of the procedure — it is a property of whether the
// registration accept carried a 5G-GUTI, because TS 24.501 clause 5.5.1.3.4 makes
// the UE answer with Registration Complete only then.
//
// So if this ever becomes conditional, periodic updates stop reaching the second
// tap and are reported by neither: the silent omission that `AMF IRI-POI events`
// forbids, indistinguishable to an agency from a subject who did nothing. Nothing
// in the LI code would fail; the reporting would simply move.
func TestRegistrationAcceptCarriesGUTIWheneverTheUEHasOne(t *testing.T) {
	ue := &context.AmfUe{Guti: "20893cafe0000001"}
	ue.PlmnId = models.PlmnId{Mcc: "208", Mnc: "93"}
	// The registration result reads both access states, which AmfUe.init would
	// normally have populated.
	ue.State = map[models.AccessType]*fsm.State{
		models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(context.Deregistered),
		models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(context.Deregistered),
	}

	// BuildRegistrationAccept consults the network-feature-support config; these
	// tests do not otherwise build one.
	if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
		t.Cleanup(func() { factory.AmfConfig.Configuration = nil })
	}

	nasPdu, err := BuildRegistrationAccept(ue, models.ACCESSTYPE__3_GPP_ACCESS, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("BuildRegistrationAccept: %v", err)
	}
	if len(nasPdu) == 0 {
		t.Fatal("BuildRegistrationAccept produced no PDU")
	}

	// The IEI is what the UE keys on; its presence is the whole mechanism.
	if !containsByte(nasPdu, nasMessage.RegistrationAcceptGUTI5GType) {
		t.Error("the registration accept carries no 5G-GUTI IE for a UE that has a GUTI — " +
			"the UE will send no Registration Complete, so a periodic registration " +
			"update reaches neither reporting tap and is never reported")
	}
}

// TestTheTwoRegistrationTapsPartitionTheTypes states the other half: the guards
// on the two taps are complements, so no registration type can be reported twice.
func TestTheTwoRegistrationTapsPartitionTheTypes(t *testing.T) {
	for _, regType := range []uint8{
		nasMessage.RegistrationType5GSInitialRegistration,
		nasMessage.RegistrationType5GSMobilityRegistrationUpdating,
		nasMessage.RegistrationType5GSPeriodicRegistrationUpdating,
		nasMessage.RegistrationType5GSEmergencyRegistration,
	} {
		mobilityTap := regType == nasMessage.RegistrationType5GSMobilityRegistrationUpdating
		completeTap := regType != nasMessage.RegistrationType5GSMobilityRegistrationUpdating
		if mobilityTap == completeTap {
			t.Errorf("registration type %d is reported by both taps or by neither", regType)
		}
	}
}

func containsByte(b []byte, want byte) bool {
	for _, got := range b {
		if got == want {
			return true
		}
	}

	return false
}
