package sqlInject

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
)

type BaseSqlInject struct {
	injectAttacks.BaseInject
}

func NewBaseSqlInject(target base.BaseTarget) *BaseSqlInject {
	return &BaseSqlInject{BaseInject: injectAttacks.BaseInject{
		BaseTarget: target,
	}}
}
