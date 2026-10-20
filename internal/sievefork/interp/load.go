package interp

import (
	"context"
	"fmt"
	"strings"

	"github.com/EvalAlan/elemta/internal/sievefork/lexer"
	"github.com/EvalAlan/elemta/internal/sievefork/parser"
)

var supportedRequires = map[string]struct{}{
	"fileinto":          {},
	"envelope":          {},
	"encoded-character": {},

	"comparator-i;octet":           {},
	"comparator-i;ascii-casemap":   {},
	"comparator-i;ascii-numeric":   {},
	"comparator-i;unicode-casemap": {},

	"imap4flags":  {},
	"variables":   {},
	"relational":  {},
	"copy":        {},
	"reject":      {},
	"ereject":     {},
	"subaddress":  {},
	"environment": {},
	"body":        {},
	// Added in this fork (see ../FORK.md).
	"regex":            {},
	"mailbox":          {},
	"date":             {},
	"vacation":         {},
	"vacation-seconds": {},
}

var (
	commands map[string]func(*Script, parser.Cmd) (Cmd, error)
	tests    map[string]func(*Script, parser.Test) (Test, error)
)

func init() {
	// break initialization loop

	commands = map[string]func(*Script, parser.Cmd) (Cmd, error){
		// RFC 5228
		"require":  loadRequire,
		"if":       loadIf,
		"elsif":    loadElsif,
		"else":     loadElse,
		"stop":     loadStop,
		"fileinto": loadFileInto, // fileinto extension
		"redirect": loadRedirect,
		"keep":     loadKeep,
		"discard":  loadDiscard,
		// RFC 5232 (imap4flags extension)
		"setflag":    loadSetFlag,
		"addflag":    loadAddFlag,
		"removeflag": loadRemoveFlag,
		// RFC 5229 (variables extension)
		"set": loadSet,
		// RFC 5429 (reject/ereject extensions)
		"reject":  loadReject,
		"ereject": loadEReject,
		// RFC 5230 (vacation extension), added in this fork
		"vacation": loadVacation,
		// vnd.dovecot.testsuite
		"test":                loadTestSuiteTest,
		"test_set":            loadTestSuiteTestSet,
		"test_fail":           loadTestSuiteTestFail,
		"test_binary_load":    loadTestSuiteBinaryLoad,
		"test_binary_save":    loadTestSuiteBinarySave,
		"test_mailbox_create": loadTestSuiteMailboxCreate,
		// "test_imap_metadata_set"
		"test_config_reload": loadNoop, // go-sieve applies changes immediately
		"test_config_set":    loadTestSuiteConfigSet,
		"test_config_unset":  loadTestSuiteConfigUnset,
		"test_result_reset":  loadTestSuiteResultReset,
		"test_message":       loadTestSuiteCmdMessage,
	}
	tests = map[string]func(*Script, parser.Test) (Test, error){
		// RFC 5228
		"address":  loadAddressTest,
		"allof":    loadAllOfTest,
		"anyof":    loadAnyOfTest,
		"envelope": loadEnvelopeTest, // envelope extension
		"exists":   loadExistsTest,
		"false":    loadFalseTest,
		"true":     loadTrueTest,
		"header":   loadHeaderTest,
		"not":      loadNotTest,
		"size":     loadSizeTest,
		// RFC 5229 (variables extension)
		"string": loadStringTest,
		// RFC 5232 (imap4flags extension)
		"hasflag": loadHasFlagTest,
		// RFC 5183 (environment extension)
		"environment": loadEnvironmentTest,
		// RFC 5173 (body extension)
		"body": loadBodyTest,
		// RFC 5260 (date extension), added in this fork
		"date":        loadDateTest,
		"currentdate": loadCurrentDateTest,
		// vnd.dovecot.testsuite
		"test_script_compile": loadTestSuiteCompile,       // compile script (to test for compile errors)
		"test_script_run":     loadTestSuiteRun,           // run script (to test for run-time errors)
		"test_error":          loadTestSuiteError,         // check detailed results of test_script_compile or test_script_run
		"test_message":        loadTestSuiteTestMessage,   // check results of test_result_execute - where messages are
		"test_result_action":  loadTestSuiteResultAction,  // check results of test_result_execute - what actions are executed
		"test_result_execute": loadTestSuiteResultExecute, // apply script results (validated using test_message)
	}
}

func LoadScript(cmdStream []parser.Cmd, opts *Options) (*Script, error) {
	s := &Script{
		extensions: map[string]struct{}{},
		opts:       opts,
	}

	loadedCmds, err := LoadBlock(s, cmdStream)
	if err != nil {
		return nil, err
	}
	s.cmd = loadedCmds

	return s, nil
}

func LoadBlock(s *Script, cmds []parser.Cmd) ([]Cmd, error) {
	loaded := make([]Cmd, 0, len(cmds))
	for _, c := range cmds {
		cmd, err := LoadCmd(s, c)
		if err != nil {
			return nil, fmt.Errorf("LoadCmd %s: %w", c.Id, err)
		}
		if cmd == nil {
			continue
		}
		loaded = append(loaded, cmd)
	}
	return loaded, nil
}

func LoadCmd(s *Script, cmd parser.Cmd) (Cmd, error) {
	cmdName := strings.ToLower(cmd.Id)
	factory := commands[cmdName]
	if factory == nil {
		return nil, lexer.ErrorAt(cmd, "LoadBlock: unsupported command: %v", cmdName)
	}
	return factory(s, cmd)

}

func LoadTest(s *Script, t parser.Test) (Test, error) {
	testName := strings.ToLower(t.Id)
	factory := tests[testName]
	if factory == nil {
		return nil, lexer.ErrorAt(t, "LoadTest: unsupported test: %v", testName)
	}
	return factory(s, t)
}

type CmdNoop struct{}

func (c CmdNoop) Execute(_ context.Context, _ *RuntimeData) error {
	return nil
}

func loadNoop(_ *Script, _ parser.Cmd) (Cmd, error) {
	return CmdNoop{}, nil
}
