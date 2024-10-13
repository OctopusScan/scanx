package baseLine

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
)

type BaselineScan struct {
	base.BaseTarget
	baselines []baseLineCheck
}

func (b *BaselineScan) StartAttack() ([]result.VulMessage, error) {
	b.addBaselineCheck(newHttpOnlyCheck())
	b.addBaselineCheck(newUnsafeTLSSL())
	b.addBaselineCheck(newUnsafeHttpHeader())
	var checkRes []result.VulMessage
	for _, v := range b.baselines {
		ok, res := v.check(b.BaseTarget)
		if ok {
			checkRes = append(checkRes, res...)
		}
	}
	return checkRes, nil
}

func (b *BaselineScan) addBaselineCheck(check ...baseLineCheck) {
	for _, v := range check {
		b.baselines = append(b.baselines, v)
	}
}

func NewBaseLineScanner(target base.BaseTarget) *BaselineScan {
	return &BaselineScan{BaseTarget: target}
}
