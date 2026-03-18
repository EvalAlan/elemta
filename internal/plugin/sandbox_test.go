package plugin

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateResourceUsageIncludesCPU(t *testing.T) {
	sandbox := NewPluginSandbox(DefaultSandboxConfig())
	sandbox.cpuUsageProvider = func(_ *SandboxedExecution) (float64, error) {
		return 12.5, nil
	}

	execution := &SandboxedExecution{
		ID:         "exec-1",
		PluginName: "cpu-check",
		StartTime:  time.Now(),
		ResourceUsage: &ResourceUsage{
			LastUpdated: time.Now(),
		},
	}

	sandbox.updateResourceUsage(execution)
	assert.Equal(t, 12.5, execution.ResourceUsage.CPUPercent)
	assert.GreaterOrEqual(t, execution.ResourceUsage.MemoryMB, int64(0))
	assert.Greater(t, execution.ResourceUsage.Goroutines, 0)
}

func TestCheckResourceLimitsEnforcesCPULimit(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.MaxCPUPercent = 10
	sandbox := NewPluginSandbox(cfg)
	sandbox.resourceMonitor = &ResourceMonitor{}
	sandbox.cpuUsageProvider = func(_ *SandboxedExecution) (float64, error) {
		return 80, nil
	}

	execution := &SandboxedExecution{
		ID:         "exec-2",
		PluginName: "cpu-limit",
		StartTime:  time.Now(),
		ResourceUsage: &ResourceUsage{
			LastUpdated: time.Now(),
		},
	}

	err := sandbox.checkResourceLimits(execution)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "cpu limit exceeded"), err.Error())
}
