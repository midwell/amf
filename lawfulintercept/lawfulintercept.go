// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package lawfulintercept is the AMF's Lawful Interception IRI-POI. It receives
// interception tasks over X1 (mutual TLS), matches AMF events against tasked
// targets, and delivers the resulting xIRI to an MDF2 over X2. It is opt-in:
// inactive — and silent — unless the AMF is started with LI credentials, so an
// AMF that is not intercepting behaves and looks exactly as before.
package lawfulintercept

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	amfctx "github.com/omec-project/amf/context"
	liasn1 "github.com/omec-project/li/asn1"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
	"github.com/omec-project/nas/v2/nasMessage"
	"github.com/omec-project/openapi/v2/models"
)

// Config configures the AMF LI IRI-POI. Init is only called when LI is enabled.
type Config struct {
	X1Listen string // address for the X1 provisioning listener, e.g. ":8443"
	MDF2     string // X2 delivery destination (MDF2 "host:port")
	NEID     string // this network element's identifier (echoed in X1 responses)
	Cert     string // X0-pre-provisioned LI PKI: this NE's certificate
	Key      string //                            its private key
	CACert   string //                            the LI CA trust anchor

	AdmfURL          string        // ADMF X1 endpoint for NE-initiated issue reports (empty = disabled)
	AdmfID           string        // the responsible ADMF's identifier (for reports)
	KeepaliveTimeout time.Duration // purge tasking if no X1 message within this (0 = disabled)
}

// sender delivers an xIRI/xCC PDU to an MDF. *x2x3.Client satisfies it; tests
// inject a capturing implementation to assert per-warrant delivery isolation.
type sender interface {
	Send(*x2x3.PDU) error
}

type subsystem struct {
	store    *store.Store
	client   sender
	iriCtx   *liasn1.Context
	neID     string
	reporter *x1.Reporter // nil when NE-initiated reporting is not configured
}

// active holds the running subsystem, or nil when LI is not configured.
var active atomic.Pointer[subsystem]

// Init starts the AMF LI IRI-POI: it loads the LI credentials, opens the X1
// listener (mutual TLS), and prepares X2 delivery to the MDF2. Call it once at
// AMF startup, only when LI is configured.
func Init(cfg Config) error {
	mat, err := mtls.Load(cfg.Cert, cfg.Key, cfg.CACert)
	if err != nil {
		return err
	}
	st := store.New()
	var reporter *x1.Reporter
	if cfg.AdmfURL != "" {
		reporter = x1.NewReporter(cfg.AdmfURL, cfg.AdmfID, cfg.NEID, mat.ClientTLS())
	}
	// Deliver X2 asynchronously: the Report* hooks run on the per-UE GMM/NAS
	// goroutine (some before the downlink NAS is even built), so a slow or
	// unreachable MDF2 must never block them — that would delay a targeted UE's
	// signalling, a target-observable timing side channel and an availability risk
	// (review R3b; design D11 mandates async X2 delivery). Worker delivery failures
	// surface to the ADMF over X1 (throttled, NE-level, no target id), never a log.
	client := x2x3.NewAsyncSender(
		x2x3.NewClient(cfg.MDF2, mat.ClientTLS()), 0,
		func(error) {
			if reporter != nil {
				_ = reporter.ReportNEIssue(x1.NEIssueMDFUnreachable, "MDF2 X2 delivery failed")
			}
		},
		nil, // drops are covered by the same MDF-unreachable report from the worker
	)
	sub := &subsystem{
		store:    st,
		client:   client,
		iriCtx:   iri.NewContext(),
		neID:     cfg.NEID,
		reporter: reporter,
	}
	x1srv := x1.NewServer(st, cfg.NEID, x1.OnActivate(sub.reportStartOfInterception))
	// Bind the X1 listener synchronously so a bind/permission failure is reported
	// to the caller — otherwise LI would look enabled (active.Store below) while
	// no X1 tasking can ever be received.
	ln, err := net.Listen("tcp", cfg.X1Listen)
	if err != nil {
		// Surface the failure to the ADMF over X1 too (an operational fault, not a
		// per-target signal), best-effort.
		if sub.reporter != nil {
			_ = sub.reporter.ReportNEIssue(x1.NEIssueX1ListenFailed, "X1 listener bind failed")
		}
		return fmt.Errorf("lawful interception: X1 listen on %s: %w", cfg.X1Listen, err)
	}
	srv := &http.Server{Handler: x1srv, TLSConfig: mat.ServerTLS()}
	// Certificates come from TLSConfig, so the file arguments are empty.
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	// Keepalive fail-safe: purge tasking if the ADMF goes silent (TS 103 221-1).
	if cfg.KeepaliveTimeout > 0 {
		go x1srv.WatchKeepalive(cfg.KeepaliveTimeout)
	}
	active.Store(sub)
	return nil
}

// ReportRegistration emits a registration xIRI for ue if it matches an active
// interception task. A mobility registration update — the UE informing the
// network it has moved while staying registered — is reported as an
// AMFLocationUpdate; every other registration type is an AMFRegistration. It is
// a no-op when LI is inactive or ue is not a target, and never logs anything
// that would reveal interception.
func ReportRegistration(ue *amfctx.AmfUe) {
	sub := active.Load()
	if sub == nil || ue == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(ue), registrationEvent(ue))
}

// registrationEvent picks the xIRI for a completed registration: a mobility
// registration update is an AMFLocationUpdate (the UE reporting movement while
// staying registered); any other type is an AMFRegistration.
func registrationEvent(ue *amfctx.AmfUe) any {
	if ue.RegistrationType5GS == nasMessage.RegistrationType5GSMobilityRegistrationUpdating {
		return amfLocationUpdate(ue)
	}
	return amfRegistration(ue)
}

// ReportDeregistration emits an AMFDeregistration xIRI for ue if it matches an
// active task. networkInitiated distinguishes a network-ordered deregistration
// from a UE-originating one; access is the access type being deregistered.
// No-op and silent when LI is inactive or ue is not a target.
func ReportDeregistration(ue *amfctx.AmfUe, networkInitiated bool, access models.AccessType) {
	sub := active.Load()
	if sub == nil || ue == nil {
		return
	}
	dir := iri.DirUEInitiated
	if networkInitiated {
		dir = iri.DirNetworkInitiated
	}
	sub.deliverIRI(sub.matchingTasks(ue), amfDeregistration(ue, dir, accessType(access)))
}

// ReportRegistrationReject emits an AMFUnsuccessfulProcedure xIRI (failed
// procedure = registration) for ue if it matches an active task; cause is the
// 5GMM reject cause. At reject time ue may be only partially identified — if no
// target identifier is yet known it matches no task and nothing is emitted.
// No-op and silent when LI is inactive.
func ReportRegistrationReject(ue *amfctx.AmfUe, cause uint8) {
	sub := active.Load()
	if sub == nil || ue == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(ue), amfUnsuccessfulRegistration(ue, cause))
}

// ReportIdentifierAssociation emits an AMFIdentifierAssociation xIRI for ue if
// it matches an active task — the AMF has bound the target's SUPI to a 5G-GUTI
// (a GUTI carried to the UE in a Registration Accept). No-op and silent when LI
// is inactive or ue is not a target.
func ReportIdentifierAssociation(ue *amfctx.AmfUe) {
	sub := active.Load()
	if sub == nil || ue == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(ue), amfIdentifierAssociation(ue))
}

// ReportIdentifierDeassociation emits an AMFIdentifierDeassociation xIRI for ue
// if it matches an active task — the AMF has released the target's SUPI↔5G-GUTI
// binding (on deregistration). No-op and silent when LI is inactive or ue is
// not a target.
func ReportIdentifierDeassociation(ue *amfctx.AmfUe) {
	sub := active.Load()
	if sub == nil || ue == nil {
		return
	}
	sub.deliverIRI(sub.matchingTasks(ue), amfIdentifierDeassociation(ue))
}

// reportStartOfInterception runs when a task is newly activated over X1. It
// scans the AMF UE pool and, for every already-registered UE the task targets,
// emits an AMFStartOfInterceptionWithRegisteredUE — so a warrant that arrives
// after the UE is already on the network still produces an initial record.
func (s *subsystem) reportStartOfInterception(task types.InterceptTask) {
	if !task.WantsProduct(types.ProductIRI) {
		return
	}
	var events []any
	amfctx.AMF_Self().UePool.Range(func(_, value any) bool {
		ue, ok := value.(*amfctx.AmfUe)
		if !ok {
			return true
		}
		// Read ue's identifiers and state under ue.Mutex and build the record here.
		// The ue.State map's keys are fixed at UE creation (only the per-access
		// *fsm.State values transition, via Set), so ranging it does not risk the
		// fatal "concurrent map iteration and write". The lock is best-effort for the
		// value/identifier reads: the NAS write paths do not currently take ue.Mutex,
		// so it establishes ordering only against other ue.Mutex holders. The scan
		// emits only for already-Registered UEs, whose SUPI/PEI/GPSI/TMSI are stable
		// after the registration that set them — so the residual window is narrow.
		// Closing it fully requires the NAS write paths to take ue.Mutex (a broader
		// AMF concurrency change, tracked as review R1).
		ue.Mutex.Lock()
		if registered(ue) && taskTargets(task, ue) {
			events = append(events, amfStartOfInterception(ue))
		}
		ue.Mutex.Unlock()
		return true
	})
	if len(events) == 0 {
		return
	}
	// Delivery is asynchronous (enqueue-and-return; see Init), so this X1 callback
	// never blocks on the MDF; hand the built records to the delivery client.
	for _, ev := range events {
		s.deliverIRI([]types.InterceptTask{task}, ev)
	}
}

// deliverIRI encodes event once and delivers it as an X2 xIRI to every task in
// tasks that wants IRI product. It is silent on any error (encoding or
// delivery) so that interception can never be inferred from AMF behaviour.
func (s *subsystem) deliverIRI(tasks []types.InterceptTask, event any) {
	if len(tasks) == 0 {
		return
	}
	payload, err := iri.EncodeXIRI(s.iriCtx, event)
	if err != nil {
		return
	}
	for _, t := range tasks {
		if !t.WantsProduct(types.ProductIRI) {
			continue
		}
		// Delivery is asynchronous (see Init): Send enqueues and returns, so this
		// signalling path never blocks on the MDF; delivery failures are reported
		// to the ADMF over X1 from the delivery worker, not here.
		_ = s.client.Send(&x2x3.PDU{
			Type:          x2x3.PDUTypeX2,
			PayloadFormat: x2x3.PayloadFormat3GPP33128,
			Direction:     x2x3.DirectionNotApplicable,
			XID:           parseXID(t.XID),
			Payload:       payload,
		})
	}
}

// matchingTasks returns the active tasks targeting any of ue's identifiers,
// de-duplicated by task id.
func (s *subsystem) matchingTasks(ue *amfctx.AmfUe) []types.InterceptTask {
	var out []types.InterceptTask
	seen := map[types.XID]bool{}
	for _, id := range targetsOf(ue) {
		for _, t := range s.store.Match(id) {
			if !seen[t.XID] {
				seen[t.XID] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// targetsOf returns ue's known 5G target identifiers, with the AMF's "type-"
// prefixes stripped to the bare value the X1 tasking uses.
func targetsOf(ue *amfctx.AmfUe) []types.TargetIdentifier {
	var ids []types.TargetIdentifier
	if v := afterPrefix(ue.Supi, "imsi-", "nai-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetSUPI, Value: v})
	}
	if v := afterPrefix(ue.Pei, "imeisv-", "imei-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetPEI, Value: v})
	}
	if v := afterPrefix(ue.Gpsi, "msisdn-", "extid-"); v != "" {
		ids = append(ids, types.TargetIdentifier{Type: types.TargetGPSI, Value: v})
	}
	return ids
}

// amfRegistration maps an AmfUe to a TS 33.128 AMFRegistration record. The
// registration type is taken from the NAS 5GS registration request; the result
// defaults to 3GPP-access.
func amfRegistration(ue *amfctx.AmfUe) iri.AMFRegistration {
	return iri.AMFRegistration{
		RegistrationType:   registrationType(ue),
		RegistrationResult: iri.RegResult3GPPAccess,
		SUPI:               supiChoice(ue),
		PEI:                peiChoice(ue),
		GPSI:               gpsiChoice(ue),
		GUTI:               fiveGGUTI(ue),
	}
}

// amfLocationUpdate maps an AmfUe to a TS 33.128 AMFLocationUpdate record,
// emitted when a mobility registration update tells the AMF the UE has moved.
// The Location subtree is kept minimal (see li/iri.Location); the detailed
// cell/TAI encoding is a later increment.
func amfLocationUpdate(ue *amfctx.AmfUe) iri.AMFLocationUpdate {
	return iri.AMFLocationUpdate{
		SUPI:     supiChoice(ue),
		PEI:      peiChoice(ue),
		GPSI:     gpsiChoice(ue),
		GUTI:     fiveGGUTI(ue),
		Location: iri.Location{LocationInfo: iri.LocationInfo{CurrentLocation: true}},
	}
}

// amfDeregistration maps an AmfUe to a TS 33.128 AMFDeregistration record.
func amfDeregistration(ue *amfctx.AmfUe, dir iri.AMFDirection, access iri.AccessType) iri.AMFDeregistration {
	return iri.AMFDeregistration{
		DeregistrationDirection: dir,
		AccessType:              access,
		SUPI:                    supiChoice(ue),
		PEI:                     peiChoice(ue),
		GPSI:                    gpsiChoice(ue),
		GUTI:                    fiveGGUTI(ue),
	}
}

// amfUnsuccessfulRegistration maps a rejected registration to a TS 33.128
// AMFUnsuccessfulProcedure record with a 5GMM failure cause.
func amfUnsuccessfulRegistration(ue *amfctx.AmfUe, cause uint8) iri.AMFUnsuccessfulProcedure {
	return iri.AMFUnsuccessfulProcedure{
		FailedProcedureType: iri.FailedRegistration,
		FailureCause:        iri.FiveGMMCause(cause),
		SUPI:                supiChoice(ue),
		PEI:                 peiChoice(ue),
		GPSI:                gpsiChoice(ue),
		GUTI:                fiveGGUTI(ue),
	}
}

// amfStartOfInterception maps an already-registered AmfUe to a TS 33.128
// AMFStartOfInterceptionWithRegisteredUE record.
func amfStartOfInterception(ue *amfctx.AmfUe) iri.AMFStartOfInterceptionWithRegisteredUE {
	return iri.AMFStartOfInterceptionWithRegisteredUE{
		RegistrationResult: iri.RegResult3GPPAccess,
		RegistrationType:   registrationType(ue),
		SUPI:               supiChoice(ue),
		PEI:                peiChoice(ue),
		GPSI:               gpsiChoice(ue),
		GUTI:               fiveGGUTI(ue),
	}
}

// amfIdentifierAssociation maps an AmfUe to a TS 33.128 AMFIdentifierAssociation
// record binding the target's SUPI to its assigned 5G-GUTI.
func amfIdentifierAssociation(ue *amfctx.AmfUe) iri.AMFIdentifierAssociation {
	return iri.AMFIdentifierAssociation{
		SUPI: supiChoice(ue),
		PEI:  peiChoice(ue),
		GPSI: gpsiChoice(ue),
		GUTI: fiveGGUTI(ue),
	}
}

// amfIdentifierDeassociation maps an AmfUe to a TS 33.128
// AMFIdentifierDeassociation record releasing the target's SUPI↔5G-GUTI binding.
func amfIdentifierDeassociation(ue *amfctx.AmfUe) iri.AMFIdentifierDeassociation {
	return iri.AMFIdentifierDeassociation{
		SUPI: supiChoice(ue),
		GUTI: fiveGGUTI(ue),
	}
}

// supiChoice returns ue's SUPI as the iri "supi" CHOICE arm (IMSI or NAI), or
// nil when the AMF holds no SUPI in a form we can map. A nil in a mandatory SUPI
// field makes encoding fail, which deliverIRI swallows silently.
func supiChoice(ue *amfctx.AmfUe) any {
	if v, ok := strings.CutPrefix(ue.Supi, "imsi-"); ok {
		return iri.IMSI(v)
	}
	if v, ok := strings.CutPrefix(ue.Supi, "nai-"); ok {
		return iri.NAI(v)
	}
	return nil
}

// peiChoice returns ue's PEI as the iri "pei" CHOICE arm (IMEI or IMEISV), or
// nil (an absent optional).
func peiChoice(ue *amfctx.AmfUe) any {
	if v, ok := strings.CutPrefix(ue.Pei, "imeisv-"); ok {
		return iri.IMEISV(v)
	}
	if v, ok := strings.CutPrefix(ue.Pei, "imei-"); ok {
		return iri.IMEI(v)
	}
	return nil
}

// gpsiChoice returns ue's GPSI as the iri "gpsi" CHOICE arm (MSISDN), or nil.
func gpsiChoice(ue *amfctx.AmfUe) any {
	if v, ok := strings.CutPrefix(ue.Gpsi, "msisdn-"); ok {
		return iri.MSISDN(v)
	}
	return nil
}

// registrationType maps the NAS 5GS registration type to the TS 33.128 value.
func registrationType(ue *amfctx.AmfUe) iri.AMFRegistrationType {
	switch ue.RegistrationType5GS {
	case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
		return iri.RegTypeMobility
	case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
		return iri.RegTypePeriodic
	case nasMessage.RegistrationType5GSEmergencyRegistration:
		return iri.RegTypeEmergency
	default:
		return iri.RegTypeInitial
	}
}

// accessType maps a 3GPP access type to the TS 33.128 enumeration.
func accessType(a models.AccessType) iri.AccessType {
	if a == models.ACCESSTYPE_NON_3_GPP_ACCESS {
		return iri.AccessNonThreeGPP
	}
	return iri.AccessThreeGPP
}

// registered reports whether ue is in the Registered state on any access.
func registered(ue *amfctx.AmfUe) bool {
	for _, st := range ue.State {
		if st != nil && st.Is(amfctx.Registered) {
			return true
		}
	}
	return false
}

// taskTargets reports whether task's target matches any of ue's identifiers.
func taskTargets(task types.InterceptTask, ue *amfctx.AmfUe) bool {
	return slices.Contains(targetsOf(ue), task.Target)
}

// fiveGGUTI builds the 5G-GUTI from the AMF's served GUAMI and ue's 5G-TMSI.
// The GUAMI's 6-hex AmfId encodes RegionID(8b) | SetID(10b) | Pointer(6b).
func fiveGGUTI(ue *amfctx.AmfUe) iri.FiveGGUTI {
	g := iri.FiveGGUTI{FiveGTMSI: int64(uint32(ue.Tmsi))}
	guamis := amfctx.AMF_Self().ServedGuamiList
	if len(guamis) == 0 {
		return g
	}
	sg := guamis[0]
	g.MCC = sg.PlmnId.Mcc
	g.MNC = sg.PlmnId.Mnc
	if b, err := hex.DecodeString(sg.AmfId); err == nil && len(b) == 3 {
		v := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		g.AMFRegionID = int(v >> 16 & 0xFF)
		g.AMFSetID = int(v >> 6 & 0x3FF)
		g.AMFPointer = int(v & 0x3F)
	}
	return g
}

// parseXID converts an X1 task id (a UUID string) to the 16-byte XID carried in
// the X2 PDU header. On any parse failure it returns the zero XID (best-effort).
func parseXID(xid types.XID) [16]byte {
	var out [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(string(xid), "-", ""))
	if err == nil && len(b) == len(out) {
		copy(out[:], b)
	}
	return out
}

// afterPrefix returns s with the first matching prefix removed, or "" if none
// match (an identifier we cannot map is treated as not present).
func afterPrefix(s string, prefixes ...string) string {
	for _, p := range prefixes {
		if v, ok := strings.CutPrefix(s, p); ok {
			return v
		}
	}
	return ""
}
