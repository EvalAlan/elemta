package webmail

import (
	"os"
	"testing"
)

// Most tests here check what a send produced, at once; undo send's delay
// would hold every message back. Tests of undo send choose a delay.
func TestMain(m *testing.M) {
	defaultUndoSend = 0
	os.Exit(m.Run())
}
