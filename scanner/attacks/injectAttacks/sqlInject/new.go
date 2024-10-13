package sqlInject

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewSqlInjectAttack(target base.BaseTarget, config conf.DbsScanConfig) (bool, attacks.Attack) {
	return true, NewSqlInject(target, config)
}
