package counter

import (
	"github.com/wedkarz02/aes256go/src/consts"
)

type Counter struct {
	Bytes [consts.COUNTER_SIZE]byte
}

func NewCounter() *Counter {
	return &Counter{}
}

func (c *Counter) Increment() {
	for i := consts.COUNTER_SIZE - 1; i >= 0; i-- {
		c.Bytes[i]++
		if c.Bytes[i] != 0 {
			break
		}
	}
}
