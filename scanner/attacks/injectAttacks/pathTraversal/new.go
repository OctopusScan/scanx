package pathTraversal

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewPathTraversalScan(target base.BaseTarget) (bool, attacks.Attack) {
	return true, NewPathTraversalScanner(target)
}
