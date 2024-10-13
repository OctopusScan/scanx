package main

import (
	"fmt"
	"net/url"
)

func main() {
	a, e := url.Parse("http://127.0.0.1:8080/aaa/bbb/ccc?a=1&b=2")
	fmt.Println(e)
	fmt.Println(a.Scheme + "://" + a.Host + a.Path)
}
