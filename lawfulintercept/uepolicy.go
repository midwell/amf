// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package lawfulintercept

import (
	"sync"

	amfctx "github.com/omec-project/amf/context"
)

// The UE policy delivery service message types this package reads, TS 24.501 table D.6.1.1.
// A UE policy container holds one such message: the PTI in its first octet and the message
// type in its second (tables D.5.1.1.1 and D.5.2.1.1).
const (
	uePolicyCommand       = 0x01 // MANAGE UE POLICY COMMAND
	uePolicyComplete      = 0x02 // MANAGE UE POLICY COMPLETE
	uePolicyCommandReject = 0x03 // MANAGE UE POLICY COMMAND REJECT
)

// Bounds on the COMMANDs held while their answers are awaited. A procedure is normally one
// PTI at a time, retransmitted under the same PTI on T3501, so a UE rarely holds more than
// one. The total bound covers UEs that leave without answering and without deregistering
// from every access; past it a new COMMAND is not held, and its COMPLETE produces no record.
const (
	maxPendingPerUE   = 4
	maxPendingUEs     = 1024
	uePolicyHeaderLen = 2
)

// pendingCommand is a COMMAND relayed to a UE and not yet answered.
type pendingCommand struct {
	pti     uint8
	command []byte
}

// pendingPolicies holds, per UE, the MANAGE UE POLICY COMMANDs this AMF relayed to it, so the
// AMFUEPolicyTransfer the UE's COMPLETE triggers can carry the COMMAND it confirms. The zero
// value is ready to use.
type pendingPolicies struct {
	mu   sync.Mutex
	byUE map[*amfctx.AmfUe][]pendingCommand
}

// remember holds command for ue under pti, replacing a COMMAND held under the same PTI — a
// T3501 retransmission, or a new procedure reusing the value.
func (p *pendingPolicies) remember(ue *amfctx.AmfUe, pti uint8, command []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.byUE == nil {
		p.byUE = map[*amfctx.AmfUe][]pendingCommand{}
	}
	held, known := p.byUE[ue]
	if !known && len(p.byUE) >= maxPendingUEs {
		return
	}
	for i := range held {
		if held[i].pti == pti {
			held = append(held[:i], held[i+1:]...)
			break
		}
	}
	if len(held) >= maxPendingPerUE {
		held = held[1:]
	}
	p.byUE[ue] = append(held, pendingCommand{pti: pti, command: append([]byte(nil), command...)})
}

// take removes and returns the COMMAND held for ue under pti, or nil.
func (p *pendingPolicies) take(ue *amfctx.AmfUe, pti uint8) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	held := p.byUE[ue]
	for i := range held {
		if held[i].pti != pti {
			continue
		}
		command := held[i].command
		held = append(held[:i], held[i+1:]...)
		if len(held) == 0 {
			delete(p.byUE, ue)
		} else {
			p.byUE[ue] = held
		}
		return command
	}
	return nil
}

// forget drops everything held for ue.
func (p *pendingPolicies) forget(ue *amfctx.AmfUe) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.byUE, ue)
}

// NoteUEPolicyCommand is the downlink half of the UE policy record: the AMF relaying a UE
// policy container to the UE. It produces no record. TS 33.128 clause 6.2.2.2.12 triggers
// AMFUEPolicyTransfer on the UE's MANAGE UE POLICY COMPLETE, and makes its uEPolicy the
// MANAGE UE POLICY COMMAND that COMPLETE confirms, so a COMMAND relayed to a UE under a
// warrant is held until its answer arrives.
//
// Only a UE some task matches is held for, so a subscriber under no warrant costs nothing
// here. The consequence is that a task activated between a COMMAND and its COMPLETE does not
// report that exchange: the COMPLETE finds nothing held.
//
// No-op and silent when LI is inactive or ue is not a target.
func NoteUEPolicyCommand(ue *amfctx.AmfUe, container []byte) {
	sub := active.Load()
	if sub == nil || ue == nil || len(container) < uePolicyHeaderLen || container[1] != uePolicyCommand {
		return
	}
	if len(sub.matchingTasks(ue.IdentitySnapshot())) == 0 {
		return
	}
	sub.policies.remember(ue, container[0], container)
}

// ReportUEPolicyComplete is the uplink half: the AMF passing a UE policy container from the UE
// to the PCF in Namf_Communication_N1MessageNotify. A MANAGE UE POLICY COMPLETE produces one
// AMFUEPolicyTransfer carrying the COMMAND held under its PTI. A COMPLETE with nothing held —
// its COMMAND relayed before the UE was a target, or not held for the bounds above — produces
// none, because the record's uEPolicy is mandatory and the COMPLETE itself is not that
// content. A MANAGE UE POLICY COMMAND REJECT ends the procedure without a record, since the
// clause names only the COMPLETE. The policy is copied, never parsed beyond those two octets.
//
// No-op and silent when LI is inactive or ue is not a target.
func ReportUEPolicyComplete(ue *amfctx.AmfUe, container []byte) {
	sub := active.Load()
	if sub == nil || ue == nil || len(container) < uePolicyHeaderLen {
		return
	}
	switch container[1] {
	case uePolicyComplete:
		command := sub.policies.take(ue, container[0])
		if command == nil {
			return
		}
		id := ue.IdentitySnapshot()
		sub.reportEvent(id, amfUEPolicyTransfer(id, command))
	case uePolicyCommandReject:
		sub.policies.take(ue, container[0])
	}
}
