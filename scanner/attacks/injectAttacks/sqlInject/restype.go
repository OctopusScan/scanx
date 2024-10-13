package sqlInject

type sqlScanType struct {
	isTimeBase   bool
	paramName    string
	payload      string
	dbms         string
	requestDump  string
	responseDump string
	injectType   string
}
