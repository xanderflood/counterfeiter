package robbers

type PizzaBandit interface {
	StealAndEat(p Pizza)
}

type Pizza struct{}
