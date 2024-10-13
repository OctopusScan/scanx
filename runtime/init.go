package runtime

func Init(enableLog bool) error {
	initDecoration(enableLog)
	return nil
}
