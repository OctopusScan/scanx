package utils

import (
	"github.com/google/uuid"
	"github.com/mfonda/simhash"
	"github.com/sergi/go-diff/diffmatchpatch"
	"math/rand"
)

func RemoveDuplicateStrings(strList []string) []string {
	stringMap := make(map[string]bool)
	for _, str := range strList {
		stringMap[str] = true
	}
	newStrList := []string{}
	for key := range stringMap {
		if key != "" {
			newStrList = append(newStrList, key)
		}
	}
	return newStrList
}
func GenerateRandomString(length int) string {
	uuidObj, _ := uuid.NewUUID()
	uuidString := uuidObj.String()
	var seed int64
	for _, c := range uuidString {
		seed += int64(c)
	}
	rand.Seed(seed)
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func CopyMap(srcMap map[string]interface{}) map[string]interface{} {
	var nweMap = make(map[string]interface{})
	for k, v := range srcMap {
		nweMap[k] = v
	}
	return nweMap
}
func StrDiffBySimHash(str1 string, str2 string) uint8 {
	str1_byte := []byte(str1)
	str2_byte := []byte(str2)
	a := simhash.Simhash(simhash.NewWordFeatureSet(str1_byte))
	b := simhash.Simhash(simhash.NewWordFeatureSet(str2_byte))
	return simhash.Compare(a, b)
}

// 去除差异字符串
func DiffContent(strs []string) string {
	if len(strs) != 2 {
		return ""
	}
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(strs[0], strs[1], false)
	var result string
	for _, diff := range diffs {
		if diff.Type == diffmatchpatch.DiffEqual {
			result += diff.Text
		}
	}
	return result
}
