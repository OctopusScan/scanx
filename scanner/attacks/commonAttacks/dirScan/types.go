package dirScan

type Path struct {
	Common []string
	Jsmap  []string
}

type DirScanResults struct {
	ErrorUpperLimitExitType ExitType `json:"error_upper_limit_exitType"`
	Target                  string   `json:"target"`
	Paths                   Path     `json:"paths"`
}

type dirScanTargetTask struct {
	IsRandomCheckPath bool
	ChildPath         []string
	IsTimeOut         bool   //这是否是一个超时任务
	TargetUrl         string // 目标url
	Path              string // 目录爆破的payload，即访问的路径
}

type dirScanResult struct {
	IsRandomCheckPath bool
	IsEverTimeout     bool //这是否是一个timeout后重试的请求
	Code              int
	Target            string
	Path              string
}
