package crawler

import (
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/base"
	"strings"
)

type CrawlerMTEC struct {
	*Multitasking.BaseExecuteController
	crawlerTarget []base.BaseTarget
}

func NewCrawlerMTEC() *CrawlerMTEC {
	return &CrawlerMTEC{
		BaseExecuteController: Multitasking.NewBaseExecuteController(),
	}
}

func (c *CrawlerMTEC) AddTarget(target base.BaseTarget) {
	c.crawlerTarget = append(c.crawlerTarget, target)
}
func (c *CrawlerMTEC) CheckTargetRepeat(target base.BaseTarget) bool {
	nowUrl := target.Url
	if strings.Contains(nowUrl, "?") {
		nowUrl = strings.Split(nowUrl, "?")[0]
	}
	nowVariations, _ := base.ParseUri(target.Url, []byte(target.RequestBody), target.Method, target.ContentType, target.Headers)
	for _, v := range c.crawlerTarget {
		orgUrl := v.Url
		if strings.Contains(orgUrl, "?") {
			orgUrl = strings.Split(orgUrl, "?")[0]
		}
		orgVariations, _ := base.ParseUri(v.Url, []byte(v.RequestBody), v.Method, v.ContentType, v.Headers)
		if nowUrl == orgUrl && v.Method == target.Method {
			for _, o := range orgVariations.Params {
				if stringInParams(o.Name, nowVariations.Params) {
					continue
				}
				return false
			}
			return true
		}
	}
	return false
}
func stringInParams(str string, params []base.Param) bool {
	for _, v := range params {
		if v.Name == str {
			return true
		}
	}
	return false
}
