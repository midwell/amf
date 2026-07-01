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
	"net/http"
	"strings"
	"sync/atomic"

	amfctx "github.com/omec-project/amf/context"
	liasn1 "github.com/omec-project/li/asn1"
	"github.com/omec-project/li/iri"
	"github.com/omec-project/li/mtls"
	"github.com/omec-project/li/store"
	"github.com/omec-project/li/types"
	"github.com/omec-project/li/x1"
	"github.com/omec-project/li/x2x3"
)

// Config configures the AMF LI IRI-POI. Init is only called when LI is enabled.
type Config struct {
	X1Listen string // address for the X1 provisioning listener, e.g. ":8443"
	MDF2     string // X2 delivery destination (MDF2 "host:port")
	NEID     string // this network element's identifier (echoed in X1 responses)
	Cert     string // X0-pre-provisioned LI PKI: this NE's certificate
	Key      string //                            its private key
	CACert   string //                            the LI CA trust anchor
}

type subsystem struct {
	store  *store.Store
	client *x2x3.Client
	iriCtx *liasn1.Context
	neID   string
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
	sub := &subsystem{
		store:  st,
		client: x2x3.NewClient(cfg.MDF2, mat.ClientTLS()),
		iriCtx: iri.NewContext(),
		neID:   cfg.NEID,
	}
	srv := &http.Server{
		Addr:      cfg.X1Listen,
		Handler:   x1.NewServer(st, cfg.NEID),
		TLSConfig: mat.ServerTLS(),
	}
	// Certificates come from TLSConfig, so the file arguments are empty.
	go func() { _ = srv.ListenAndServeTLS("", "") }()
	active.Store(sub)
	return nil
}

// ReportRegistration emits an AMFRegistration xIRI for ue if it matches an
// active interception task. It is a no-op when LI is inactive or ue is not a
// target, and never logs anything that would reveal interception.
func ReportRegistration(ue *amfctx.AmfUe) {
	sub := active.Load()
	if sub == nil || ue == nil {
		return
	}
	sub.reportRegistration(ue)
}

func (s *subsystem) reportRegistration(ue *amfctx.AmfUe) {
	tasks := s.matchingTasks(ue)
	if len(tasks) == 0 {
		return
	}
	payload, err := iri.EncodeXIRI(s.iriCtx, amfRegistration(ue))
	if err != nil {
		return
	}
	for _, t := range tasks {
		if !t.WantsProduct(types.ProductIRI) {
			continue
		}
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

// amfRegistration maps an AmfUe to a TS 33.128 AMFRegistration record.
// registrationType/result default to Initial / 3GPP-access for now; the exact
// type from the NAS 5GS registration request is a follow-up.
func amfRegistration(ue *amfctx.AmfUe) iri.AMFRegistration {
	reg := iri.AMFRegistration{
		RegistrationType:   iri.RegTypeInitial,
		RegistrationResult: iri.RegResult3GPPAccess,
		GUTI:               fiveGGUTI(ue),
	}
	if v, ok := strings.CutPrefix(ue.Supi, "imsi-"); ok {
		reg.SUPI = iri.IMSI(v)
	} else if v, ok := strings.CutPrefix(ue.Supi, "nai-"); ok {
		reg.SUPI = iri.NAI(v)
	}
	if v, ok := strings.CutPrefix(ue.Pei, "imeisv-"); ok {
		reg.PEI = iri.IMEISV(v)
	} else if v, ok := strings.CutPrefix(ue.Pei, "imei-"); ok {
		reg.PEI = iri.IMEI(v)
	}
	if v, ok := strings.CutPrefix(ue.Gpsi, "msisdn-"); ok {
		reg.GPSI = iri.MSISDN(v)
	}
	return reg
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
