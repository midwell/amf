// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package factory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStrictLiBlockDoesNotFailTheConfigurationLoad is a source-level assertion, and it exists
// because the property it guards was already established once and then lost.
//
// `service/li_block_containment_test.go` asserts that the Lawful Interception block cannot return
// from Start. Its guards passed while this network function was, in fact, refusing to start over a
// single mistyped LI key — because the refusal had moved one call frame earlier and into this
// package, where they could not see it. A guard scoped to where a defect was last found does not
// follow the defect, and it reads as coverage while the property is violated somewhere else.
//
// So the rule here is the other half: `strictLiBlock`'s verdict is *recorded*, never returned.
// Returning it fails InitConfigFactory, which fails Initialize, which reaches a Fatalf — taking
// the service-based interface, NGAP and every UE this AMF serves with it, over an optional
// subsystem. It is also the loudest possible disclosure that this element is LI-provisioned: a
// network function that will not start is visible to every operator, every peer and every
// monitoring system, where a log line is visible only to whoever reads logs.
//
// The refusal still happens, and interception still does not start on it. What changed is who acts
// on it: the LI subsystem, at a point where the ADMF can be told. See LiBlockError.
func TestStrictLiBlockDoesNotFailTheConfigurationLoad(t *testing.T) {
	const file = "factory.go"

	fset := token.NewFileSet()

	parsed, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}

	var found, recorded bool

	ast.Inspect(parsed, func(n ast.Node) bool {
		if call, isCall := n.(*ast.CallExpr); isCall {
			if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "strictLiBlock" {
				found = true
			}
		}

		return true
	})

	if !found {
		t.Fatalf("no call to strictLiBlock in %s; if the strict LI decode moved, move this guard "+
			"with it rather than deleting it — the property it holds is that a refused LI block "+
			"never stops the network function", file)
	}

	// The call must be the right-hand side of an assignment to liBlockErr, and nothing else. An
	// `if err := strictLiBlock(...); err != nil { return err }` is the exact shape that caused the
	// regression, and it is an assignment too — so the guard checks the target, not merely that an
	// assignment happened.
	ast.Inspect(parsed, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Rhs) != 1 {
			return true
		}

		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}

		if ident, isIdent := call.Fun.(*ast.Ident); !isIdent || ident.Name != "strictLiBlock" {
			return true
		}

		for _, lhs := range assign.Lhs {
			if target, ok := lhs.(*ast.Ident); ok && target.Name == "liBlockErr" {
				recorded = true
			}
		}

		return true
	})

	if !recorded {
		t.Errorf("%s: strictLiBlock's verdict is not recorded in liBlockErr. If it is returned "+
			"from InitConfigFactory instead, a single mistyped key in the optional `li` block "+
			"stops this whole network function — an outage, and the loudest way to disclose that "+
			"this element is LI-provisioned. Record it and let the LI subsystem refuse "+
			"interception on it, where the ADMF can be told.", file)
	}
}

// TestAMisspelledLiKeyDoesNotStopTheAMF asserts both halves, and the second is the one a previous
// round lost: the key must be refused, *and* the network function must still come up.
func TestAMisspelledLiKeyDoesNotStopTheAMF(t *testing.T) {
	const good = `info:
  version: 1.0.0
configuration:
  amfName: AMF
  li:
    x1Listen: ":8443"
    neId: amf-1
    admfUrl: https://admf:9443
    keepaliveTimeout: 30s
`

	write := func(t *testing.T, body string) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), "amfcfg.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		return path
	}

	t.Run("a conformant li block leaves no refusal recorded", func(t *testing.T) {
		orig := AmfConfig
		t.Cleanup(func() { AmfConfig = orig; liBlockErr = nil })

		if err := InitConfigFactory(write(t, good)); err != nil {
			t.Fatalf("a conformant li block was refused: %v", err)
		}
		// A reload that fixes the block must clear the recorded refusal, or one bad load
		// disables interception for the life of the process.
		if err := LiBlockError(); err != nil {
			t.Errorf("a conformant li block left a refusal recorded: %v", err)
		}
	})

	for _, typo := range []string{"keepaliveTimeut", "admf_url"} {
		t.Run(typo, func(t *testing.T) {
			orig := AmfConfig
			t.Cleanup(func() { AmfConfig = orig; liBlockErr = nil })

			body := strings.Replace(good, "keepaliveTimeout", typo, 1)
			if typo == "admf_url" {
				body = strings.Replace(good, "admfUrl", typo, 1)
			}

			if err := InitConfigFactory(write(t, body)); err != nil {
				t.Fatalf("a misspelled LI key stopped the whole configuration load, which stops "+
					"the network function: %v", err)
			}

			err := LiBlockError()
			if err == nil {
				t.Fatalf("%s was accepted, so the setting the operator wrote never reached the "+
					"element and its unsafe default stands with nothing saying so", typo)
			}
			if !strings.Contains(err.Error(), typo) {
				t.Errorf("the refusal does not name the key that was wrong: %v", err)
			}
		})
	}
}

// TestTheStrictLiDecodeIsStillStrict guards the other direction. The fix above is a narrow one —
// who acts on the refusal — and it must not be read, or implemented, as backing out the strictness
// that produced it.
func TestTheStrictLiDecodeIsStillStrict(t *testing.T) {
	const body = `info:
  version: 1.0.0
configuration:
  li:
    x1Listen: ":8443"
    neId: amf-1
    keepaliveTimeut: 30s
`

	if err := strictLiBlock([]byte(body)); err == nil {
		t.Error("a misspelled LI key was accepted by the strict decode; the containment fix is " +
			"about who acts on the refusal, not about whether there is one")
	}
}
