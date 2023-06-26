package main

import (
	"fmt"

	"github.com/wedkarz02/aes256-go/aes256"
)

func main() {
	sbox := aes256.NewSBox()
	for i, el := range sbox {
		if i%0x10 == 0 {
			fmt.Println()
		}

		fmt.Printf("%x\t", el)
	}
	fmt.Println()

	xk, err := aes256.NewEncKey([]byte("supersecretkeythathastobe32bytes"))
	if err != nil {
		panic(err)
	}

	for _, row := range *xk {
		for _, chr := range row {
			fmt.Printf("%v ", string(chr))
		}
		fmt.Println()
	}
}
