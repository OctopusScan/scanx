package xssInject

import (
	"crypto/tls"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/zyylhn/httpc"
	"go.uber.org/ratelimit"
	"net/http"
	"testing"
	"time"
)

func newSession(ratelimiter int) (*base.Session, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: -1,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}

	_client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(1) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client := httpc.NewWithClient(_client)
	return &base.Session{
		Client:      client,
		RateLimiter: ratelimit.New(ratelimiter),
	}, nil
}

func TestAA(t *testing.T) {
	//httpxSession, _ := newSession(50)

	//response, _ := base.Request("http://127.0.0.1:8765/vul/xss/xss_reflected_get.php?message=%3Cscript%3Ealert(%271%27)%3C/script%3E&submit=submit", "GET", "", false, nil, httpxSession)
	//
	//ctx, _ := context.WithCancel(context.Background())
	//opts := append(chromedp.DefaultExecAllocatorOptions[:],
	//	chromedp.Flag("proxy-server", "http://localhost:0"), //禁用网络链接
	//	chromedp.Flag("headless", false),                    //设置为false以禁用无头模式
	//	chromedp.Flag("disable-gpu", true),
	//	chromedp.Flag("disable-extensions", true),
	//	chromedp.Flag("disable-network", true),
	//)
	//ctx, _ = chromedp.NewExecAllocator(ctx, opts...)
	//ctx, _ = chromedp.NewContext(ctx)
	//chromedp.ListenTarget(ctx, func(ev interface{}) {
	//	if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
	//		fmt.Println("1111111")
	//		go func() {
	//			chromedp.Run(ctx,
	//				page.HandleJavaScriptDialog(true),
	//			)
	//		}()
	//		//if ev.(*page.EventJavascriptDialogOpening).Message == x.xssPayloadRandomNum {
	//		//	go func() {
	//		//		chromedp.Run(ctx,
	//		//			page.HandleJavaScriptDialog(true),
	//		//		)
	//		//	}()
	//		//} else {
	//		//	go func() {
	//		//		chromedp.Run(ctx,
	//		//			page.HandleJavaScriptDialog(true),
	//		//		)
	//		//	}()
	//		//}
	//	}
	//})
	//
	//for {
	//	chromedp.Run(ctx, chromedp.Navigate("data:text/html,"+"<script>alert(1)</script>"))
	//	time.Sleep(1 * time.Second)
	//}

	//cancel()

}
