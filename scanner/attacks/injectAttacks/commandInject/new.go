package commandInject

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewCommandInjectAttack(target base.BaseTarget, config conf.CommandInjectConfig) (bool, attacks.Attack) {
	commandInject := NewCommandInject(target, config)
	if commandInject != nil {
		return true, commandInject
	}
	return false, nil
}
