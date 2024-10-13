package dirScan

import (
	"github.com/B9O2/Multitasking"
)

type ExitType string

const (
	NetworkUnreachableError ExitType = "NetworkUnreachableError"
	UnreliableResultsError  ExitType = "UnreliableResultsError"
)

type HyperEC struct {
	*Multitasking.BaseExecuteController
	errorNum   int
	retryLimit int
	exitType   ExitType
}

func NewHyperEC(retryLimit int) *HyperEC {
	return &HyperEC{BaseExecuteController: Multitasking.NewBaseExecuteController(),
		retryLimit: retryLimit,
	}
}
func (h *HyperEC) GetErrorNum() int {
	return h.errorNum
}
func (h *HyperEC) SetErrorNum(errNum int) {
	h.errorNum = errNum
}
func (h *HyperEC) SetErrorType(exitType ExitType) {
	h.exitType = exitType
}
func (h *HyperEC) GetErrorType() ExitType {
	return h.exitType
}
func (h *HyperEC) CheckTerminate(task *dirScanTargetTask) {
	if h.errorNum > h.retryLimit {
		h.Terminate()
	}
	if task.IsTimeOut {
		h.errorNum++
	}
}
