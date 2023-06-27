package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/wedkarz02/aes256-go/aes256"
)

func ReadTestFile(fileName string) ([][]byte, error) {
	file, err := os.Open(fileName)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var keys [][]byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		data := strings.Split(scanner.Text(), " ")
		keyStr := strings.Join(data, "")

		bytes, err := hex.DecodeString(keyStr)
		if err != nil {
			return nil, err
		}

		keys = append(keys, bytes)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func TestKeyExp(k []byte, expk []byte) (bool, string, error) {
	c, err := aes256.NewAES256(k)

	if err != nil {
		return false, "error", err
	}

	for i, b := range c.ExpandedKey {
		if b != expk[i] {
			desc := fmt.Sprintf("Wrong byte found: %x instead of %x at index %v", b, expk[i], i)
			return false, desc, nil
		}
	}

	return true, "Correct output", nil
}

func RunKeyTest() {
	testKeys, err := ReadTestFile("keyvec-test.txt")
	if err != nil {
		panic(err)
	}

	xTestKeys, err := ReadTestFile("xkeyvec-test.txt")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Status\tKey_num\tDescription\n")

	for i, k := range testKeys {
		ok, desc, err := TestKeyExp(k, xTestKeys[i])

		if err != nil {
			panic(err)
		}

		fmt.Printf("%v\t%v\t%v\n", map[bool]string{true: "Passed", false: "Failed"}[ok], i, desc)
	}
}

func main() {
	RunKeyTest()
}
