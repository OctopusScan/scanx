package base

type fileReaderCheckFlags struct {
	OsType     Os
	FileName   string
	CheckPoint []string
}

var FileReaderCheckFlags = []fileReaderCheckFlags{
	{OsType: Linux, FileName: "etc{separator}passwd", CheckPoint: []string{"root:x", "daemon:x", "/usr/sbin/nologin"}},
	{OsType: Windows, FileName: "Windows{separator}win.ini", CheckPoint: []string{"[extensions]"}},
	{OsType: Linux, FileName: "WEB-INF{separator}web.xml", CheckPoint: []string{"web-app xmlns"}},
	{OsType: Windows, FileName: "WEB-INF{separator}web.xml", CheckPoint: []string{"web-app xmlns"}},
}

var OsSeparators = map[Os]string{
	Linux:   "/",
	Windows: "\\",
}
