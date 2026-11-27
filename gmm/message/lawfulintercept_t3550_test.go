// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package message

import "testing"

// TestT3550RunningOutReportsTheRegistration: when the UE never answers the REGISTRATION
// ACCEPT, T3550's last expiry sets the access 5GMM-REGISTERED (TS 24.501 clause 5.5.1.2.8
// case c). That is the trigger of TS 33.128 clause 6.2.2.2.2, so the registration is reported
// there, once, and before the registration request data it describes is cleared.
//
// Read from the source rather than driven: the expiry runs on the timer's goroutine, which
// writes ue.T3550 unsynchronised with SendRegistrationAccept's own write of it, so a test
// that lets the timer run out trips the race detector on code this test is not about.
func TestT3550RunningOutReportsTheRegistration(t *testing.T) {
	calls := callsIn(t, "SendRegistrationAccept")

	if got := count(calls, "liReportRegistration"); got != 1 {
		t.Fatalf("SendRegistrationAccept reports the registration %d times, want 1, when T3550 runs out", got)
	}
	report := firstIndex(calls, "liReportRegistration")
	cleared := firstIndex(calls, "ue.ClearRegistrationRequestData")
	if cleared < 0 || report > cleared {
		t.Errorf("the registration is reported at %d and its request data cleared at %d; "+
			"the report must come first", report, cleared)
	}
}
