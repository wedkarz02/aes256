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

	invsbox := aes256.NewInvSBox(sbox)
	for i, el := range invsbox {
		if i%0x10 == 0 {
			fmt.Println()
		}

		fmt.Printf("%x\t", el)
	}
	fmt.Println()
}
