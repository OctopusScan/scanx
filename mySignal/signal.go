package mySignal

type AppDownSignal struct {
}

func (a AppDownSignal) String() string {
	return "appDown"
}

func (a AppDownSignal) Signal() {
}

func NewAppDownSignal() AppDownSignal {
	return AppDownSignal{}
}
