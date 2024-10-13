package commonAttacks

import "github.com/OctopusScan/webVulScanEngine/conf"

func DirScan(config conf.DirScanConfig) *CommonAttackCtx {
	return &CommonAttackCtx{
		attackType: Dir,
		config: conf.DirScanConfig{
			DirScanMaxRetryLimit:          config.DirScanMaxRetryLimit,
			DirScanMaxRootCheckRetryLimit: config.DirScanMaxRootCheckRetryLimit,
			Threads:                       config.Threads,
		},
	}
}

func JsonpScan() *CommonAttackCtx {
	return &CommonAttackCtx{
		attackType: Jsonp,
	}
}

func UploadScan(config conf.UploadScanConfig) *CommonAttackCtx {
	return &CommonAttackCtx{
		attackType: Upload,
		config:     config,
	}
}

func BaseLineCheck() *CommonAttackCtx {
	return &CommonAttackCtx{
		attackType: BaseLine,
		config:     nil,
	}
}
