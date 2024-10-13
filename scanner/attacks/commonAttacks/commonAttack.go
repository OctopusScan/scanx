package commonAttacks

import "github.com/OctopusScan/webVulScanEngine/scanner/attacks"

type CommonType int

const (
	Dir CommonType = iota
	Upload
	Jsonp
	BaseLine
)

type CommonAttackCtx struct {
	attackType CommonType
	config     interface{}
}

func (c CommonAttackCtx) GetConfig() interface{} {
	return c.config
}

func (c CommonAttackCtx) GetAttackType() interface{} {
	return c.attackType
}

type CommonAttack interface {
	attacks.Attack
}
