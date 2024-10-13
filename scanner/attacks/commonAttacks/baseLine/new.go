package baseLine

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewBaselineScan(target base.BaseTarget) (bool, attacks.Attack) {
	return true, NewBaseLineScanner(target)
}
