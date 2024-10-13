package uploadScan

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
)

func NewUploadScan(target base.BaseTarget, config conf.UploadScanConfig) (bool, attacks.Attack) {
	return true, NewUploadScanner(target, config)

}
