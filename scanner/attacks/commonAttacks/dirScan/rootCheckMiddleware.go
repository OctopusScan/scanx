package dirScan

import (
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/conf"
)

type RootCheckMiddleWare struct {
	f      func(interface{}, Multitasking.ExecuteController, string, conf.DirScanConfig) interface{}
	errNum *int
	target string
	conf   conf.DirScanConfig
}

func (mm *RootCheckMiddleWare) Run(ec Multitasking.ExecuteController, i interface{}) interface{} {
	return mm.f(i, ec, mm.target, mm.conf)
}

func newRootCheckMiddleWare(f func(interface{}, Multitasking.ExecuteController, string, conf.DirScanConfig) interface{}, target string, conf conf.DirScanConfig) *RootCheckMiddleWare {
	return &RootCheckMiddleWare{
		target: target,
		conf:   conf,
		f:      f,
	}
}

func rootCheckMiddlewareFunc(i interface{}, ec Multitasking.ExecuteController, target string, config conf.DirScanConfig) interface{} {
	//fmt.Println("rootCheckErrNum", *maxErrorNum)
	hec := ec.(*HyperEC)
	maxErrorNum := hec.GetErrorNum()
	if maxErrorNum > config.DirScanMaxRetryLimit {
		//fmt.Println("RootCheckDone")
		hec.Terminate()
	}
	if i != nil {
		switch i.(type) {
		case []string:
			childPath := i.([]string)
			for _, v := range childPath {
				ec.InheritDC().AddTask(&dirScanTargetTask{
					TargetUrl: target,
					Path:      v,
				})
			}
		case *dirScanResult:
			res := i.(*dirScanResult)
			if res.IsRandomCheckPath {
				//设置maxErrorNum,该次扫描结果不可信
				maxErrorNum = config.DirScanMaxRetryLimit + 1
				hec.SetErrorType(UnreliableResultsError)
				hec.SetErrorNum(maxErrorNum)
				hec.Terminate()
			}
			if res.IsEverTimeout {
				maxErrorNum = 0
				hec.SetErrorNum(maxErrorNum)
			}
		}

	}
	return i
}
