package scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks/baseLine"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks/dirScan"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks/jsonpScan"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks/uploadScan"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks/commandInject"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks/pathTraversal"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks/sqlInject"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks/xssInject"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks/xxeInject"
	"github.com/zyylhn/httpc"
	"go.uber.org/ratelimit"
	"net/http"
	"net/url"
)

var defaultResolvers = []string{
	"1.1.1.1",         // Cloudflare
	"1.0.0.1",         // Cloudlfare secondary
	"8.8.8.8",         // Google
	"8.8.4.4",         // Google secondary
	"223.5.5.5",       // AliDNS
	"223.6.6.6",       // AliDNS
	"119.29.29.29",    // DNSPod
	"114.114.114.114", // 114DNS
	"114.114.115.115", // 114DNS
}

type Scanner struct {
	Config  conf.Config
	Target  base.BaseTarget
	Attacks []attacks.Attack
}

func NewScanner(config conf.Config, target base.BaseTarget) (*Scanner, error) {
	if target.ContentType != "" {
		target.Headers["Content-Type"] = string(target.ContentType)
	} else {
		target.Headers["Content-Type"] = string(base.ApplicationUrlencoded)
	}
	httpxSession, err := newSession(config)
	if err != nil {
		return nil, err
	}
	target.HttpxSession = httpxSession
	checkresp, err := target.SendRequest("", base.Param{}, base.DefaultRequestOptionsWithoutRetry)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%s 资源请求错误 err:%s", target.Url, err.Error()))
	}
	if checkresp.StatusCode == 404 {
		return nil, errors.New(fmt.Sprintf("%s 资源不存在", target.Url))

	}
	return &Scanner{
		Config:  config,
		Target:  target,
		Attacks: nil,
	}, nil
}

func (scan *Scanner) Scan() []result.VulMessage {
	var allScanResult []result.VulMessage
	for _, attack := range scan.Attacks {
		res, err := attack.StartAttack()
		if err != nil {
			MainInsp.Print(useful.ERROR, FileName("scanner.go"), useful.Text(fmt.Sprintf("scan error %v", err)))
			continue
		}
		allScanResult = append(allScanResult, res...)
	}
	return allScanResult
}

func (scan *Scanner) LoadAttacks(attackTypes ...attacks.AttackType) error {
	var err error
	for _, attackType := range attackTypes {
		err = scan.loadAttack(attackType)
		if err != nil {
			return err
		}
	}
	return err
}

func (scan *Scanner) loadAttack(attackType attacks.AttackType) error {
	switch attackType.(type) {
	case *injectAttacks.InjectTypeCtx:
		switch attackType.GetAttackType().(injectAttacks.InjectType) {
		case injectAttacks.Command:
			commandInjectConfig := attackType.GetConfig().(conf.CommandInjectConfig)
			ok, commandInjectPlugin := commandInject.NewCommandInjectAttack(scan.Target, commandInjectConfig)
			if ok {
				scan.Attacks = append(scan.Attacks, commandInjectPlugin)
			}
		case injectAttacks.XSS:
			xssConfig := attackType.GetConfig().(conf.XSScanConfig)
			ok, xssAttackPlugin := xssInject.NewXssAttack(scan.Target, xssConfig)
			if ok {
				scan.Attacks = append(scan.Attacks, xssAttackPlugin)
			}
		case injectAttacks.Dbs:
			dbsConfig := attackType.GetConfig().(conf.DbsScanConfig)
			//ok, dbsAttackPlugin := dbsInject.NewDbsAttack(scan.Target, dbsConfig)
			ok, dbsAttackPlugin := sqlInject.NewSqlInjectAttack(scan.Target, dbsConfig)
			if ok {
				scan.Attacks = append(scan.Attacks, dbsAttackPlugin)
			}
		case injectAttacks.PathTraversal:
			ok, pathTraversalPlugin := pathTraversal.NewPathTraversalScan(scan.Target)
			if ok {
				scan.Attacks = append(scan.Attacks, pathTraversalPlugin)
			}
		case injectAttacks.XXE:
			ok, xxeScanPlugin := xxeInject.NewXXEAttack(scan.Target)
			if ok {
				scan.Attacks = append(scan.Attacks, xxeScanPlugin)
			}
		default:
			return errors.New("未知插件")
		}
	case *commonAttacks.CommonAttackCtx:
		switch attackType.GetAttackType().(commonAttacks.CommonType) {
		case commonAttacks.Dir:
			dirConfig := attackType.GetConfig().(conf.DirScanConfig)
			ok, dirScanPlugin := dirScan.NewDirScan(scan.Target, dirConfig)
			if ok {
				scan.Attacks = append(scan.Attacks, dirScanPlugin)
			}
		case commonAttacks.Jsonp:
			ok, jsonpPlugin := jsonpScan.NewJsonpScan(scan.Target)
			if ok {
				scan.Attacks = append(scan.Attacks, jsonpPlugin)
			}
		case commonAttacks.Upload:
			if len(scan.Target.Mimes) == 0 {
				MainInsp.Print(useful.WARN, FileName("scanner.go"), useful.Text(fmt.Sprintf("upload插件启用失败,未检测到任何MIMEHeader")))
				return nil
			}
			uploadConfig := attackType.GetConfig().(conf.UploadScanConfig)
			ok, uploadScanPlugin := uploadScan.NewUploadScan(scan.Target, uploadConfig)
			if ok {
				scan.Attacks = append(scan.Attacks, uploadScanPlugin)
			}
		case commonAttacks.BaseLine:
			ok, baseLineCheckPlugin := baseLine.NewBaselineScan(scan.Target)
			if ok {
				scan.Attacks = append(scan.Attacks, baseLineCheckPlugin)
			}
		default:
			return errors.New("未知插件")
		}
	}
	return nil
}

//func (scan *Scanner) loadInjectAttack(injectType injectAttacks.InjectType) error {
//	switch injectType {
//
//	}
//	return nil
//}
//
//func (scan *Scanner) loadCommonAttack(commonType commonAttacks.CommonType) error {
//	switch commonType {
//
//	}
//	return nil
//}

func newSession(config conf.Config) (*base.Session, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: -1,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	if config.WebScan.Proxy != "" {
		proxyUrl, err := url.Parse(config.WebScan.Proxy)
		if err != nil {
			MainInsp.Print(useful.ERROR, FileName("request.go"), useful.Text(fmt.Sprintf("Httpx proxy error: %v", err)))
			return nil, err
		}
		if isSupportedProtocol(proxyUrl.Scheme) {
			transport.Proxy = http.ProxyURL(proxyUrl)
		} else {
			MainInsp.Print(useful.WARN, FileName("request.go"), useful.Text(fmt.Sprintf("Unsupported httpx proxy protocol: %s", proxyUrl.Scheme)))
		}
	}
	_client := &http.Client{
		Transport: transport,
		Timeout:   config.WebScan.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client := httpc.NewWithClient(_client)
	return &base.Session{
		ProxyPool:   config.WebScan.ProxyPool,
		Client:      client,
		RateLimiter: ratelimit.New(config.Ratelimit),
	}, nil
}
func isSupportedProtocol(value string) bool {
	return value == "http" || value == "https" || value == "socks5"
}
