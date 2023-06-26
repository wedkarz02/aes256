package main

import (
	"fmt"

	"github.com/wedkarz02/aes256-go/aes256"
	"github.com/wedkarz02/aes256-go/aes256/consts"
)

func main() {
	xk, err := aes256.NewEncKey([]byte("supersecretkeythathastobe32bytes"))
	if err != nil {
		panic(err)
	}

	for i, b := range *xk {
		if i%consts.KEY_SIZE == 0 {
			fmt.Println()
		}

		fmt.Printf("%x ", b)
	}

	fmt.Println(len(xk) / consts.KEY_SIZE)
}
