package dirScan

import (
	"github.com/OctopusScan/webVulScanEngine/utils"
	"path/filepath"
	"sort"
	"strings"
)

func loadPath() (map[string][]string, error) {
	detectionTmpPath := make(map[string][]string)
	detectionPath := make(map[string][]string)
	paths := utils.GetStringLines(dirPaths)
	for _, v := range paths {
		v = strings.TrimLeft(v, "/")
		if strings.Count(v, "/") > 0 {
			root := strings.Split(v, "/")[0]
			targetFile := strings.Split(v, "/")[len(strings.Split(v, "/"))-1]
			var tmpList []string
			getParents(v, &tmpList)
			tmpList = append(tmpList, "")
			copy(tmpList[1:], tmpList[:len(tmpList)-1])
			tmpList[0] = tmpList[0] + "/" + targetFile
			_, ok := detectionTmpPath[root]
			if ok {
				detectionTmpPath[root] = append(detectionTmpPath[root], tmpList...)
			} else {
				detectionTmpPath[root] = append(tmpList)
			}
		} else {
			detectionTmpPath[v] = []string{}
		}
	}
	for k, v := range detectionTmpPath {
		if len(v) != 0 {
			tmpSince := utils.RemoveDuplicateStrings(v)
			sort.Slice(tmpSince, func(i, j int) bool {
				return len(tmpSince[i]) > len(tmpSince[j])
			})
			detectionPath[k] = tmpSince[0 : len(tmpSince)-1]
		} else {
			detectionPath[k] = []string{}
		}

	}
	return detectionPath, nil
}
func getParents(targetPath string, pathDir *[]string) {
	dir := filepath.Dir(targetPath)
	dir = strings.ReplaceAll(dir, "\\", "/")
	*pathDir = append(*pathDir, dir)
	if strings.Count(dir, "/") > 1 {
		getParents(dir, pathDir)
	}
	return
}
