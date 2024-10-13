package attacks

import (
	"github.com/OctopusScan/webVulScanEngine/result"
)

type AttackType interface {
	GetAttackType() interface{}
	GetConfig() interface{}
}

type Attack interface {
	StartAttack() ([]result.VulMessage, error)
}
