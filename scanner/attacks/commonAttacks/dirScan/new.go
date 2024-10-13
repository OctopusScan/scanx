package dirScan

import (
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
	"net/url"
)

func NewDirScan(target base.BaseTarget, config conf.DirScanConfig) (bool, attacks.Attack) {
	parseUrl, err := url.ParseRequestURI(target.Url)
	if err != nil {
		MainInsp.Print(useful.ERROR, FileName("dirScan/new.go"), useful.Text(fmt.Sprintf("目录扫描插件加载失败%s", err)))
		return false, nil
	}
	target.Url = fmt.Sprintf("%s://%s", parseUrl.Scheme, parseUrl.Host)
	if err != nil {
		MainInsp.Print(useful.ERROR, FileName("dirScan/new.go"), useful.Text(fmt.Sprintf("目录扫描插件加载失败%s", err)))
		return false, nil
	}
	dirScan, err := NewDirScanner(target, config)
	if err != nil {
		MainInsp.Print(useful.ERROR, FileName("dirScan/new.go"), useful.Text(fmt.Sprintf("目录扫描插件加载失败%s", err)))
		return false, nil
	}
	return true, dirScan
}
