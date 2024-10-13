# scanX

支持OWASP 10基本漏洞扫描的web漏洞扫描器

目前支持模块:

通用类型漏洞扫描:
- 目录扫描
  - 常见敏感路径,文件(字典来自dirsearch)
  - js.map泄露

- jsonp扫描
- 文件上传扫描(php)

注入类漏洞扫描:

- 命令注入漏洞
- sql注入漏洞
- 路径穿越漏洞
- xss漏洞
  - 该模块需运行环境安装chrome



# start

##### 从burp导出包发起扫描:

![image-20231120103720007](README/image-20231120103720007.png)

```go
func main() {
	Init()
	baseTargetFromBurp, err := utils.LoadBaseTargetFromBurp("D:\\tooooooooooools\\XRAY\\556")//burp包路径
	if err != nil {
		return
	}
	scan, err := scanner.NewScanner(conf.Config{
		WebScan: conf.WebScan{
			Proxy:   "http://127.0.0.1:8082",
			TimeOut: 10,
		},
		Ratelimit: 5000,
	}, baseTargetFromBurp)//实例化scan
	if err != nil {
		fmt.Println(err)
		return
	}
	err = scan.LoadAttacks(
		commonAttacks.DirScan(conf.DirScanDefaultConfig),
		commonAttacks.UploadScan(conf.UploadDefaultConfig),
		injectAttacks.DbsScan(conf.DbsScanDefaultConfig),
	)//加载攻击
	if err != nil {
		fmt.Println(err)
		return
	}
	res := scan.Scan()//发起扫描
	for _, v := range res {
		MainInsp.Print(useful.INFO, Json(v))
	}
}
```

##### 从自定义请求发起扫描:

```go
func main() {
	Init()//初始化日志
    
	defaultBaseTarget := base.BaseTarget{
    IsDirect: false,
    Method:   base.POST,
    Url: "http://127.0.0.1:81/upload/Pass-01/index.php",
	RequestBody: `{"id":"333"}`,
	Headers:     map[string]string{},
	ContentType: base.ApplicationJson,
	}//初始化攻击,请正确填写对应ContentType,根据ContentType解析参数设置payload


	scan, err := scanner.NewScanner(conf.Config{
		WebScan: conf.WebScan{
			Proxy:   "http://127.0.0.1:8082",
			TimeOut: 10,
		},
		Ratelimit: 5000,
	}, baseTargetFromBurp)//实例化scan
	if err != nil {
		fmt.Println(err)
		return
	}
	err = scan.LoadAttacks(
		commonAttacks.DirScan(conf.DirScanDefaultConfig),
		commonAttacks.UploadScan(conf.UploadDefaultConfig),
		injectAttacks.DbsScan(conf.DbsScanDefaultConfig),
	)//加载攻击
	if err != nil {
		fmt.Println(err)
		return
	}
	res := scan.Scan()//发起扫描
	for _, v := range res {
		MainInsp.Print(useful.INFO, Json(v))
	}
}
```

