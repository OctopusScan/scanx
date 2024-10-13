package xssInject

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewXssAttack(target base.BaseTarget, config conf.XSScanConfig) (bool, attacks.Attack) {
	xssInjectt := NewXssInject(target, config)
	if xssInjectt != nil {
		return true, xssInjectt
	}
	return false, nil
}
