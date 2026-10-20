package interp

import (
	"fmt"

	"github.com/EvalAlan/elemta/internal/sievefork/parser"
)

func loadTestSuiteTestSet(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}
	cmd := CmdTestSuiteTestSet{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MinStrCount: 1,
				MaxStrCount: 1,
				MatchStr: func(val []string) {
					cmd.VariableName = val[0]
				},
				NoVariables: true,
			},
			{
				MinStrCount: 1,
				MaxStrCount: 1,
				MatchStr: func(val []string) {
					cmd.VariableValue = val[0]
				},
			},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	if err != nil {
		return nil, err
	}

	return cmd, nil
}

func loadTestSuiteTestFail(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}
	cmd := CmdTestSuiteTestFail{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MinStrCount: 1,
				MaxStrCount: 1,
				MatchStr: func(val []string) {
					cmd.Message = val[0]
				},
			},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	cmd.At = pcmd.Position
	if err != nil {
		return nil, err
	}

	if !usedVarsAreValid(s, cmd.Message) {
		return nil, parser.ErrorAt(pcmd.Position, "invalid variable used: %v", cmd.Message)
	}

	return cmd, nil
}

func loadTestSuiteTest(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}
	cmd := CmdTestSuiteTest{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MinStrCount: 1,
				MaxStrCount: 1,
				MatchStr: func(val []string) {
					cmd.TestName = val[0]
				},
			},
		},
		AddBlock: func(cmds []Cmd) {
			cmd.Cmds = cmds
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	return cmd, err
}

func loadTestSuiteCompile(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := TestTestSuiteCompile{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.ScriptPath = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
		},
	}, test.Position, test.Args, test.Tests, nil)
	return loaded, err
}

func loadTestSuiteConfigSet(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteConfigSet{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.Key = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
			{
				MatchStr: func(val []string) {
					loaded.Value = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	return loaded, err
}

func loadTestSuiteConfigUnset(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteConfigSet{
		Unset: true,
	}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.Key = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
			{
				MatchStr: func(val []string) {
					loaded.Value = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	return loaded, err
}

func loadTestSuiteBinarySave(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteBinarySave{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.Name = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	return loaded, err
}

func loadTestSuiteBinaryLoad(s *Script, pcmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteBinaryLoad{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.Name = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
		},
	}, pcmd.Position, pcmd.Args, pcmd.Tests, pcmd.Block)
	return loaded, err
}

func loadTestSuiteRun(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := TestTestSuiteRun{}
	err := LoadSpec(s, &Spec{}, test.Position, test.Args, test.Tests, nil)
	return loaded, err
}

func loadTestSuiteError(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := TestTestSuiteTestError{matcherTest: newMatcherTest()}
	err := LoadSpec(s, loaded.addSpecTags(&Spec{
		Tags: map[string]SpecTag{
			"index": {
				NeedsValue:  true,
				MinStrCount: 1,
				MaxStrCount: 1,
				NoVariables: true,
				MatchNum:    func(val int) {},
			},
		},
		Pos: []SpecPosArg{
			{
				MatchStr:    func(val []string) {},
				MinStrCount: 1,
			},
		},
	}), test.Position, test.Args, test.Tests, nil)
	return loaded, err
}

func loadTestSuiteResultAction(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := TestTestSuiteResultAction{matcherTest: newMatcherTest()}
	err := LoadSpec(s, loaded.addSpecTags(&Spec{
		Tags: map[string]SpecTag{
			"index": {
				NeedsValue:  true,
				MinStrCount: 1,
				MaxStrCount: 1,
				NoVariables: true,
				MatchNum: func(val int) {
					loaded.Index = &val
				},
			},
		},
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.Key = val
				},
				MinStrCount: 1,
			},
		},
	}), test.Position, test.Args, test.Tests, nil)
	if err != nil {
		return nil, err
	}

	if err := loaded.setKey(s, loaded.Key); err != nil {
		return nil, err
	}

	return loaded, nil
}

func loadTestSuiteResultReset(s *Script, cmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteResultReset{}
	err := LoadSpec(s, &Spec{}, cmd.Position, cmd.Args, cmd.Tests, nil)
	return loaded, err
}

func loadTestSuiteMailboxCreate(s *Script, cmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteMailboxCreate{}
	err := LoadSpec(s, &Spec{
		Pos: []SpecPosArg{
			{
				MatchStr: func(val []string) {
					loaded.Name = val[0]
				},
				MinStrCount: 1,
				MaxStrCount: 1,
			},
		},
	}, cmd.Position, cmd.Args, cmd.Tests, nil)
	return loaded, err
}

func loadTestSuiteCmdMessage(s *Script, cmd parser.Cmd) (Cmd, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := CmdTestSuiteMessage{}
	err := LoadSpec(s, &Spec{
		Tags: map[string]SpecTag{
			"index": {
				NeedsValue:  true,
				MinStrCount: 1,
				MaxStrCount: 1,
				NoVariables: true,
				MatchNum: func(val int) {
					loaded.Index = val
				},
			},
			"folder": {
				NeedsValue:  true,
				MinStrCount: 1,
				MaxStrCount: 1,
				NoVariables: true,
				MatchStr: func(val []string) {
					loaded.Folder = val[0]
				},
			},
			"smtp": {
				MatchBool: func() {
					loaded.SMTP = true
				},
			},
		},
		Pos: []SpecPosArg{
			{
				MatchNum: func(val int) {
					loaded.Index = val
				},
			},
		},
	}, cmd.Position, cmd.Args, cmd.Tests, nil)
	return loaded, err
}

func loadTestSuiteResultExecute(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := TestTestSuiteResultExecute{}
	err := LoadSpec(s, &Spec{}, test.Position, test.Args, test.Tests, nil)
	return loaded, err
}

func loadTestSuiteTestMessage(s *Script, test parser.Test) (Test, error) {
	if !s.RequiresExtension(TestSuiteExtension) || s.opts.T == nil {
		return nil, fmt.Errorf("testing environment is not enabled")
	}

	loaded := TestTestSuiteMessage{}
	err := LoadSpec(s, &Spec{
		Tags: map[string]SpecTag{
			"index": {
				NeedsValue:  true,
				MinStrCount: 1,
				MaxStrCount: 1,
				NoVariables: true,
				MatchNum: func(val int) {
					loaded.Index = val
				},
			},
			"folder": {
				NeedsValue:  true,
				MinStrCount: 1,
				MaxStrCount: 1,
				NoVariables: true,
				MatchStr: func(val []string) {
					loaded.Folder = val[0]
				},
			},
			"smtp": {
				MatchBool: func() {
					loaded.SMTP = true
				},
			},
		},
		Pos: []SpecPosArg{
			{
				MatchNum: func(val int) {
					loaded.Index = val
				},
			},
		},
	}, test.Position, test.Args, test.Tests, nil)
	return loaded, err
}
