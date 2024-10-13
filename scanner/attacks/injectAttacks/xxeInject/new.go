package xxeInject

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewXXEAttack(target base.BaseTarget) (bool, attacks.Attack) {
	xxeInject := NewXXEInject(target)
	if xxeInject != nil {
		return true, xxeInject
	}
	return false, nil
}
