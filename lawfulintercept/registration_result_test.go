// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"testing"

	amfctx "github.com/omec-project/amf/context"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/util/fsm"
	"github.com/omec-project/util/li/iri"
)

// ueRegisteredOver is the target UE with the given accesses in the Registered state and the
// others Deregistered.
func ueRegisteredOver(registered ...models.AccessType) *amfctx.AmfUe {
	ue := targetUE()
	ue.State = map[models.AccessType]*fsm.State{
		models.ACCESSTYPE__3_GPP_ACCESS:    fsm.NewState(amfctx.Deregistered),
		models.ACCESSTYPE_NON_3_GPP_ACCESS: fsm.NewState(amfctx.Deregistered),
	}
	for _, access := range registered {
		ue.State[access] = fsm.NewState(amfctx.Registered)
	}

	return ue
}

// An AMFRegistration's registrationResult is mandatory, and names the accesses the UE is
// registered over once this registration completes, as the REGISTRATION ACCEPT's 5GS
// registration result does. A constant 3GPP value would report a non-3GPP or dual
// registration as something it is not.
func TestARegistrationRecordNamesTheAccessesTheUEIsRegisteredOver(t *testing.T) {
	for _, c := range []struct {
		name       string
		completeOn models.AccessType
		registered []models.AccessType
		want       iri.AMFRegistrationResult
	}{
		{"over 3GPP", models.ACCESSTYPE__3_GPP_ACCESS, nil, iri.RegResult3GPPAccess},
		{"over non-3GPP", models.ACCESSTYPE_NON_3_GPP_ACCESS, nil, iri.RegResultNon3GPPAccess},
		{
			name:       "over non-3GPP while registered over 3GPP",
			completeOn: models.ACCESSTYPE_NON_3_GPP_ACCESS,
			registered: []models.AccessType{models.ACCESSTYPE__3_GPP_ACCESS},
			want:       iri.RegResult3GPPAndNon3GPP,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			snd := &captureSender{}
			activateIRI(t, snd, testTargetSUPI)

			ReportRegistration(ueRegisteredOver(c.registered...), c.completeOn)

			records := decodeRecords(t, snd)
			if len(records) != 1 {
				t.Fatalf("delivered %d records, want 1", len(records))
			}
			// AMFRegistration: registrationResult is member [2].
			if got := integer(t, records[0].member(t, 2)); got != int64(c.want) {
				t.Errorf("registrationResult = %d, want %d", got, c.want)
			}
		})
	}
}

// The start-of-interception record takes the accesses the UE is registered over when the
// warrant arrives; no registration is completing then.
func TestAStartOfInterceptionNamesTheAccessesTheUEIsRegisteredOver(t *testing.T) {
	for _, c := range []struct {
		registered []models.AccessType
		want       iri.AMFRegistrationResult
	}{
		{[]models.AccessType{models.ACCESSTYPE__3_GPP_ACCESS}, iri.RegResult3GPPAccess},
		{[]models.AccessType{models.ACCESSTYPE_NON_3_GPP_ACCESS}, iri.RegResultNon3GPPAccess},
		{
			[]models.AccessType{models.ACCESSTYPE__3_GPP_ACCESS, models.ACCESSTYPE_NON_3_GPP_ACCESS},
			iri.RegResult3GPPAndNon3GPP,
		},
	} {
		if got := registrationResultOf(ueRegisteredOver(c.registered...), nil); got != c.want {
			t.Errorf("registered over %v: result %d, want %d", c.registered, got, c.want)
		}
	}
}

// TS 33.128 clause 6.2.2.2.6: "Unsuccessful registration shall be reported only if the target
// UE has been successfully authenticated." A reject sent to a UE holding no valid NAS
// security context — one that failed authentication, or was refused before it — is a reject
// for an identity nobody has proven, and draws no record.
func TestARegistrationRejectIsReportedOnlyForAnAuthenticatedUE(t *testing.T) {
	for _, c := range []struct {
		name          string
		authenticated bool
		want          int
	}{
		{"authenticated", true, 1},
		{"not authenticated", false, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			snd := &captureSender{}
			activateIRI(t, snd, testTargetSUPI)

			ue := targetUE()
			ue.NgKsi = models.NgKsi{Ksi: nasMessage.NasKeySetIdentifierNoKeyIsAvailable}
			if c.authenticated {
				ue.SecurityContextAvailable = true
				ue.NgKsi = models.NgKsi{Ksi: 1}
			}

			ReportRegistrationReject(ue, nasMessage.Cause5GMMProtocolErrorUnspecified)

			if got := len(snd.pdus); got != c.want {
				t.Errorf("delivered %d records, want %d", got, c.want)
			}
		})
	}
}
