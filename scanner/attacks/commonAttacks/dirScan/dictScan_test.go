package dirScan

import (
	"fmt"
	"regexp"
	"testing"
)

func TestAA(t *testing.T) {
	regex := regexp.MustCompile(`app\.(\w+)\.js\.map`)
	results := regex.FindAllString("asdasdasdapp.asdasd.js.mapasdasd", -1)
	fmt.Println(results)
}
