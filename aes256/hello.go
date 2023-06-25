package aes256

import (
	"strconv"

	"github.com/wedkarz02/aes256-go/aes256/consts"
)

func Hello(name string) string {
	num := strconv.Itoa(int(consts.KEY_LEN))
	return "hello " + name + " from aes256 " + num
}
