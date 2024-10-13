package baseLine

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
)

type baseLineCheck interface {
	check(target base.BaseTarget) (bool, []result.VulMessage)
}
