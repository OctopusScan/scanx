package dirScan

import (
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/conf"
)

type MiniMiddleware struct {
	f      func(interface{}, Multitasking.ExecuteController, conf.DirScanConfig) interface{}
	config conf.DirScanConfig
}

func (mm *MiniMiddleware) Run(ec Multitasking.ExecuteController, i interface{}) interface{} {
	return mm.f(i, ec, mm.config)
}

func newMiniMiddleware(f func(interface{}, Multitasking.ExecuteController, conf.DirScanConfig) interface{}, config conf.DirScanConfig) *MiniMiddleware {
	return &MiniMiddleware{
		config: config,
		f:      f,
	}
}
func miniMiddlewareFunc(i interface{}, ec Multitasking.ExecuteController, config conf.DirScanConfig) interface{} {
	//fmt.Println("scanErrorNum", *maxErrorNum)
	hec := ec.(*HyperEC)
	maxErrorNum := hec.GetErrorNum()
	if i == nil {
		return nil
	}
	if maxErrorNum > config.DirScanMaxRetryLimit {
		//fmt.Println("taskDone")
		//ec.InheritDC().Terminate()
		ec.Terminate()
	}
	switch i.(type) {
	case *dirScanResult:
		res := i.(*dirScanResult)
		if res.IsEverTimeout {
			maxErrorNum = 0
			hec.SetErrorNum(maxErrorNum)
		}
		if res.Code >= 200 && res.Code < 300 {
			return i
		}
	//case *dirScanTargetTask:
	//	res := i.(*dirScanTargetTask)
	//	if res.IsTimeOut {
	//		*maxErrorNum++
	//	}
	//	return nil
	default:
		return nil
	}
	return nil
}
