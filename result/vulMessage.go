package result

import "github.com/OctopusScan/webVulScanEngine/base"

type DataType string
type Plugin string
type Level string
type VulType string
type VulSubType string

const (
	Xss              VulType = "XSS Injection"
	SqlInjection     VulType = "SQL Injection"
	DirLeak          VulType = "DirLeak"
	JsMap            VulType = "JsMapLeak"
	JsonpHijacking   VulType = "JsonpHijacking"
	CommandInjection VulType = "CommandInject"
	FileUpload       VulType = "FileUpload"
	PathTraversal    VulType = "PathTraversal"
	XXE              VulType = "XXE"
	BaseLines        VulType = "BaseLines"
)

const (
	ReflectXss               VulSubType = "Reflect Xss"
	StorageXss               VulSubType = "Storage Xss"
	SensitivePath            VulSubType = "Sensitive Path"
	SqlInjectBaseError       VulSubType = "Sql Injection Base Error"
	SqlInjectBaseTime        VulSubType = "Sql Injection Base Time"
	JsMapLeak                VulSubType = "Js Map Leak"
	JsonpHiJacking           VulSubType = "Jsonp Hijacking"
	CommandInjectionWithEcho VulSubType = "Command Injection With Echo"
	CommandInjectionWithTime VulSubType = "Command Injection With Time"
	PhpFileUpload            VulSubType = "Php File Upload"
	ArbitraryFileRead        VulSubType = "Arbitrary File Read"
	XXEFileRead              VulSubType = "XXE File Read"
	UnSafeCookie             VulSubType = "UnsafeCookie"
	UnSafeTLSSL              VulSubType = "UnsafeTLSSL"
	UnSafeHttpHeader         VulSubType = "UnsafeHttpHeader"
)

const (
	WebVul DataType = "web_vul"
)

const (
	SqlInject           Plugin = "SQL"
	XssInject           Plugin = "XSS"
	DirScan             Plugin = "DirScan"
	JsonpScan           Plugin = "JsonpScan"
	CommandInject       Plugin = "CommandInjection"
	FileUploadDetect    Plugin = "FileUploadDetect"
	PathTraversalDetect Plugin = "PathTraversalDetect"
	XXETraversalDetect  Plugin = "XXEDetect"
	BaseLine            Plugin = "BaseLineDetect"
)

const (
	Low      Level = "Low"
	High     Level = "High"
	Medium   Level = "Medium"
	Critical Level = "Critical"
)

type VulMessage struct {
	DataType DataType `json:"data_type"`
	VulnData VulnData `json:"vul_data"`
	Plugin   Plugin   `json:"plugin"`
	Level    Level    `json:"level"`
}

type VulnData struct {
	CreateTime      string          `json:"create_time"`
	VulnType        VulType         `json:"vuln_type"`
	VulnSubType     VulSubType      `json:"vuln_sub_type"`
	Target          string          `json:"target"`
	Ip              string          `json:"ip"`
	Method          base.HttpMethod `json:"method"`
	Param           string          `json:"param"`
	Payload         string          `json:"payload"`
	CURLCommand     string          `json:"curl_command"`
	Description     string          `json:"description"`
	Request         string          `json:"request"`
	Response        string          `json:"response"`
	DirScanExitType string          `json:"dir_scan_exit_type"`
}
