package injectAttacks

import "github.com/OctopusScan/webVulScanEngine/conf"

func DbsScan(config conf.DbsScanConfig) *InjectTypeCtx {
	return &InjectTypeCtx{
		attackType: Dbs,
		config:     config,
	}
}

func XSScan(config conf.XSScanConfig) *InjectTypeCtx {
	return &InjectTypeCtx{
		attackType: XSS,
		config:     config,
	}
}

func CommandInjectScan(config conf.CommandInjectConfig) *InjectTypeCtx {
	return &InjectTypeCtx{
		attackType: Command,
		config:     config,
	}
}

func PathTraversalScan() *InjectTypeCtx {
	return &InjectTypeCtx{
		attackType: PathTraversal,
		config:     nil,
	}
}
func XXEScan() *InjectTypeCtx {
	return &InjectTypeCtx{
		attackType: XXE,
		config:     nil,
	}
}
