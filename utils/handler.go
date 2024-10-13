package utils

import (
	"encoding/json"
	"github.com/OctopusScan/webVulScanEngine/base"
	"io"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
)

type BodyHandler func(request *http.Request) (interface{}, error)

func defaultRead(closer io.ReadCloser) (string, error) {
	read, err := io.ReadAll(closer)
	if err != nil {
		return "", err
	}
	closer.Close()
	return string(read), nil
}

func generateMime(bodyLines []string, index int) []base.Mime {
	var mimes []base.Mime
	var CT string
	CD := strings.Split(bodyLines[index], "Content-Disposition:")[1]
	if strings.HasPrefix(bodyLines[index+1], "Content-Type:") {
		CT = strings.Split(bodyLines[index+1], "Content-Type:")[1]
	}
	if strings.Contains(CD, "filename") {
		re := regexp.MustCompile(`filename="([^"]+)"`)
		match := re.FindStringSubmatch(CD)
		if len(match) > 1 {
			CD = strings.ReplaceAll(CD, match[1], "{FILENAME}")
			if CT != "" {
				mimes = append(mimes, base.Mime{
					IsFile:     true,
					MimeHeader: textproto.MIMEHeader{"Content-Disposition": {CD}, "Content-Type": {"{CONTENT_TYPE}"}},
				})
			} else {
				mimes = append(mimes, base.Mime{
					IsFile:     true,
					MimeHeader: textproto.MIMEHeader{"Content-Disposition": {CD}},
				})
			}
		}
	} else {
		//如果该条mimes不是filename的 那么就获取原始值
		startLine := index + 3
		for i := startLine; i < len(bodyLines); i++ {
			if strings.HasPrefix(bodyLines[i], "--") {
				var builder strings.Builder
				if CT != "" {
					for _, line := range bodyLines[startLine:i] {
						builder.WriteString(line)
					}
					joinedString := builder.String()
					mimes = append(mimes, base.Mime{
						Data:       joinedString,
						MimeHeader: textproto.MIMEHeader{"Content-Disposition": {CD}, "Content-Type": {CT}},
					})

					break
				} else {
					for _, line := range bodyLines[startLine-1 : i] {
						builder.WriteString(line)
					}
					joinedString := builder.String()
					mimes = append(mimes, base.Mime{
						Data:       joinedString,
						MimeHeader: textproto.MIMEHeader{"Content-Disposition": {CD}},
					})
					break
				}
			}
		}

	}
	return mimes
}

func applicationJHandler(r *http.Request) (interface{}, error) {
	bodyStr, err := defaultRead(r.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(bodyStr), nil)
	if strings.Contains(err.Error(), "Unmarshal(nil)") {
		return bodyStr, nil
	}
	return nil, err
}
func applicationUEHandler(r *http.Request) (interface{}, error) {
	bodyStr, err := defaultRead(r.Body)
	if err != nil {
		return nil, err
	}
	return bodyStr, err
}
func applicationMDHandler(r *http.Request) (interface{}, error) {
	var mimes []base.Mime
	bodyStr, err := defaultRead(r.Body)
	if err != nil {
		return nil, err
	}
	bodyLines := strings.Split(bodyStr, "\r\n")
	for index, _ := range bodyLines {
		if strings.HasPrefix(bodyLines[index], "Content-Disposition:") {
			mimes = append(mimes, generateMime(bodyLines, index)...)
		}
	}

	return mimes, nil
}
func applicationDfHandler(r *http.Request) (interface{}, error) {
	bodyStr, err := defaultRead(r.Body)
	if err != nil {
		return nil, err
	}
	return bodyStr, err
}
