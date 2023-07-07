package counter

import (
	"errors"

	"github.com/wedkarz02/aes256go/src/consts"
)

type Counter struct {
	Bytes [consts.COUNTER_SIZE]byte
}

func NewCounter(src []byte) (*Counter, error) {
	if len(src) != consts.COUNTER_SIZE {
		return &Counter{}, errors.New("invalid src size")
	}

	counter := new(Counter)
	copy(counter.Bytes[:], src)

	return counter, nil
}

func (c *Counter) Increment() {
	for i := consts.COUNTER_SIZE - 1; i >= 0; i-- {
		c.Bytes[i]++
		if c.Bytes[i] != 0 {
			break
		}
	}
}
