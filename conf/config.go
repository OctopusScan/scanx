package conf

import (
	"github.com/Kumengda/httpProxyPool/httpProxyPool"
	"github.com/OctopusScan/webVulScanEngine/base"
	"time"
)

type WebScan struct {
	Timeout   time.Duration
	Plugins   []string `json:"plugins"`
	Proxy     string   `json:"proxy"`
	ProxyPool *httpProxyPool.HttpProxyPool
}

type Reverse struct {
	Host   string `json:"host"`
	Domain string `json:"domain"`
}

type Config struct {
	Ratelimit int     `json:"ratelimit"`
	WebScan   WebScan `json:"webScan"`
	Passive   bool    `json:"passive"`
	Reverse   Reverse `json:"reverse"`
	Debug     bool    `json:"debug"`
}

type DirScanConfig struct {
	DirScanMaxRetryLimit          int
	DirScanMaxRootCheckRetryLimit int
	Threads                       int
}

var DirScanDefaultConfig = DirScanConfig{
	DirScanMaxRetryLimit:          300,
	DirScanMaxRootCheckRetryLimit: 100,
	Threads:                       10,
}

type UploadScanConfig struct {
	WebsiteExtension base.Extension
}

var UploadDefaultConfig = UploadScanConfig{WebsiteExtension: ""}

type DbsScanConfig struct {
	UsingTimeBase bool
}

var DbsScanDefaultConfig = DbsScanConfig{}
var CommandInjectDefaultConfig = CommandInjectConfig{
	ScanThreads: 20,
}

type XSScanConfig struct {
	Threads int
}
type CommandInjectConfig struct {
	UsingTimeBase bool
	ScanThreads   uint
}

var XSScanDefaultConfig = XSScanConfig{Threads: 10}
