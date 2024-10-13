package jsonpScan

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewJsonpScan(target base.BaseTarget) (bool, attacks.Attack) {
	return true, NewJsonpScanner(target)
}
