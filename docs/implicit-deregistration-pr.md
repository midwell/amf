<!-- PR title: feat(amf): implicit deregistration via mobile reachability timer (T3512) -->

## Summary

When a UE loses radio coverage, the gNB sends a UE Context Release Request to AMF. Today, AMF deactivates the user plane but never deregisters the UE — PDU sessions and associated SMF/UPF resources persist indefinitely. This is a resource leak that grows with every unreachable subscriber.

Per **3GPP TS 23.502 section 4.2.2.3.3**, the AMF should start a *mobile reachability timer* (aligned with T3512) when the UE transitions to CM-IDLE, and perform **implicit deregistration** when the timer expires. This PR implements that behavior.

## Problem

1. UE loses coverage → gNB sends NGAP UE Context Release Request
2. AMF releases the N2 connection (UE goes CM-IDLE) but keeps the UE registered
3. PDU sessions remain active in SMF/UPF; charging sessions stay open in CHF
4. Without periodic Registration Updates from the UE, these resources are never freed
5. The SM context release also lacked a proper cause value

## Changes

### 1. New `MobileReachabilityTimer` field on `AmfUe` (`context/amf_ue.go`)

Added a `*time.Timer` field using Go's `time.AfterFunc`. This is intentionally not reusing the existing `context.Timer` type, which is designed for NAS retransmission with `maxRetryTimes` semantics — the mobile reachability timer fires once and triggers a procedure, not a retransmission.

### 2. Start timer on UE Context Release Complete (`ngap/handler.go`)

In `HandleUEContextReleaseComplete`, after the RAN UE context is removed:

- **`UeContextN2NormalRelease`** — the normal path hit when gNB reports radio link failure for a registered UE. Timer starts unconditionally (if T3512 > 0 and UE is Registered).
- **`UeContextReleaseUeContext`** — when security context is available (UE persists). Timer starts in the `else` branch where the UE is kept.

Timer is **not** started for:
- `UeContextReleaseDueToNwInitiatedDeregistraion` — UE is already being deregistered
- `UeContextReleaseHandover` — UE is moving to a new gNB, stays CM-CONNECTED

### 3. Stop timer when UE re-contacts (`gmm/handler.go`)

Following the same pattern as T3513/T3565 timer stopping:

- **`HandleRegistrationRequest`** — UE re-registers (periodic or mobility registration update)
- **`HandleServiceRequest`** — UE sends service request (e.g., mobile-terminated data triggers paging, UE responds)

### 4. Stop timer on deregistration (`gmm/handler.go`)

- **`NetworkInitiatedDeregistrationProcedure`** — at function entry, to prevent double-firing if the timer callback races with another caller
- **`HandleDeregistrationRequest`** — UE-initiated deregistration

### 5. Set `REL_DUE_TO_5G_AN_REQUEST` cause in SM context release (`gmm/handler.go`)

The `NetworkInitiatedDeregistrationProcedure` previously passed `nil` as the cause when releasing SM contexts. Now it sends `REL_DUE_TO_5G_AN_REQUEST`, which allows SMF to set the appropriate charging termination cause in CHF Release requests.

### 6. Enable T3512 in Registration Accept (`gmm/message/build.go`)

Uncommented the T3512 IE so the UE receives the timer value from AMF. This was previously commented out with a note about UERANSIM not supporting it — UERANSIM has since added support, and without sending T3512 the UE has no configured periodic registration timer.

## Files changed

| File | Lines | Description |
|------|-------|-------------|
| `context/amf_ue.go` | +3/−2 | Add `MobileReachabilityTimer *time.Timer` field |
| `ngap/handler.go` | +26/+0 | Start timer in two release-complete cases |
| `gmm/handler.go` | +23/−1 | Stop timer in 4 handlers; set release cause |
| `gmm/message/build.go` | +5/−3 | Uncomment T3512 in Registration Accept |

## Test plan

### Build verification

```bash
cd amf && make all
cd amf && make test
```

### Integration test

1. Deploy AMF with a short `t3512Value` (e.g., 60 seconds) in Helm values
2. Connect a UE via UERANSIM
3. Stop the UE process (simulates coverage loss)
4. Verify AMF logs within ~62 seconds:
   ```
   UE Context Release Request              ← from gNB (~2s after UE stops)
   Starting mobile reachability timer for UE[imsi-...]: 1m0s
   Mobile reachability timer expired, initiating implicit deregistration
   Sending SmContext [...] Release Request to SMF
   ```
5. Verify SMF logs:
   ```
   PFCP Session Deletion Request/Response
   CHF Release Request
   PCF SM Policy Delete
   ```
6. Verify UE context is cleaned up in AMF (no stale entries)

### Re-registration test

1. Same setup with short T3512
2. Stop UE, wait 30 seconds (timer running but not expired)
3. Restart UE — it sends Registration Request
4. Verify AMF log does **not** show timer expiry (timer was cancelled)

## 3GPP references

- **TS 23.502 §4.2.2.3.3** — Network-initiated deregistration, implicit deregistration due to UE not reachable
- **TS 24.501 §5.3.7** — Mobile reachability timer, implicit deregistration timer
- **TS 29.502 §5.2.2.4** — SM Context Release with cause

## Notes

- This PR is AMF-only. UDM deregistration notification (`Nudm_UECM_DeregistrationNotification`) is deferred to a follow-up.
- The `REL_DUE_TO_5G_AN_REQUEST` cause string is not in the current openapi models enum but is a valid 3GPP-defined cause per TS 29.502. The `models.Cause` type is a string alias, so this works without model changes.
- Thread safety: `time.AfterFunc` fires in a new goroutine. The `NetworkInitiatedDeregistrationProcedure` and timer-stop paths use `Stop()` + nil-check which is safe against concurrent access given AMF's existing per-UE serialization via `AmfUe` lock patterns.
