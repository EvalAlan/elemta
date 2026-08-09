package smtp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Any code that branches on isInternalConnection has two behaviours, and only
// one of them is reachable from an ordinary test: every test connects over
// loopback, and the compose stack connects from a Docker address, so both take
// the internal branch.
//
// Three separate bugs lived in the external branch because of that — messages
// with a body over 1000 octets refused, header blocks over 10KB refused, and
// the peer classification itself matching public addresses as private. None
// were visible to any test until a public peer address could be simulated.
//
// This is the tripwire. It finds every function that branches on peer
// classification and requires each to be listed below as covered on both sides.
// Adding a new one without testing the external branch fails the build rather
// than quietly creating another blind spot.
var peerGatedFunctions = map[string]string{
	"validateLineContent": "TestExternalLongSingleLineStillRejectedAtReception, " +
		"TestExternalControlCharsStillRejectedAtReception, TestExternalOrdinaryMailIsAcceptedEndToEnd",
	"validateMessageHeaders": "TestExternalOrdinaryMailIsAcceptedEndToEnd",
	"performContentAnalysis": "TestExternalBodyOverLineLimitIsNotRejected, " +
		"TestExternalForwardedMailIsAccepted, TestLongHeaderBlockFromExternalSenderIsAccepted, " +
		"TestAbsurdHeaderBlockIsStillRejected",
}

func TestEveryPeerGatedBranchIsCoveredExternally(t *testing.T) {
	found := findPeerGatedFunctions(t)

	var untracked []string
	for _, name := range found {
		if _, ok := peerGatedFunctions[name]; !ok {
			untracked = append(untracked, name)
		}
	}
	if len(untracked) > 0 {
		sort.Strings(untracked)
		t.Errorf("these functions branch on isInternalConnection but are not recorded as "+
			"covered for external peers: %v\n\n"+
			"Loopback and Docker connections take the internal branch, so an ordinary test "+
			"never reaches the other one. Add a test using a public peer address (see "+
			"externalDataHandler), then list the function in peerGatedFunctions.",
			untracked)
	}

	var stale []string
	for name := range peerGatedFunctions {
		if !containsName(found, name) {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("these functions are recorded as peer-gated but no longer branch on "+
			"isInternalConnection: %v — remove them from peerGatedFunctions", stale)
	}
}

// findPeerGatedFunctions returns the names of functions whose bodies call
// isInternalConnection, excluding the accessor itself.
func findPeerGatedFunctions(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		name := fi.Name()
		return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	var found []string
	for _, p := range pkg {
		for path, file := range p.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				if fn.Name.Name == "isInternalConnection" {
					return true
				}
				if callsPeerGate(fn.Body) {
					found = append(found, fn.Name.Name)
					t.Logf("peer-gated: %s (%s)", fn.Name.Name, filepath.Base(path))
				}
				return true
			})
		}
	}
	sort.Strings(found)
	return found
}

func callsPeerGate(body *ast.BlockStmt) bool {
	gated := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "isInternalConnection" {
			gated = true
			return false
		}
		return true
	})
	return gated
}

func containsName(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
