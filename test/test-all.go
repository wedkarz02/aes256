package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/wedkarz02/aes256go/src/key"
)

// var genericKey = []byte("supersecretkeytobe32bytes")
// var genericPlain = []byte{
// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
// }

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
			fmt.Println(hex.EncodeToString(bytes))
			return nil, err
		}

		keys = append(keys, bytes)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return keys, nil
}

func CompareBytes(in []byte, pattern []byte) (bool, string) {
	if len(in) != len(pattern) {
		desc := fmt.Sprintf("len(in) does not match len(pattern): %v != %v", len(in), len(pattern))
		return false, desc
	}

	for i := range in {
		if in[i] != pattern[i] {
			desc := fmt.Sprintf("Wrong byte found: 0x%02x instead of 0x%02x at index %v", in[i], pattern[i], i)
			return false, desc
		}
	}

	return true, "Correct output"
}

func TestKeyExp(k []byte, expk []byte) (bool, string, error) {
	expandedKey, err := key.ExpandKey(k)

	if err != nil {
		return false, "error", err
	}

	result, desc := CompareBytes(expandedKey[:], expk)
	return result, desc, nil
}

func RunKeyTest() {
	testKeys, err := ReadTestFile("testvec/keyvec-test.txt")
	if err != nil {
		panic(err)
	}

	xTestKeys, err := ReadTestFile("testvec/xkeyvec-test.txt")
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

// func TestMixCol(state []byte, mixedState []byte, inv bool) (bool, string, error) {
// 	c, err := aes256go.NewAES256(genericKey)

// 	if err != nil {
// 		return false, "error", err
// 	}

// 	var mixedWord []byte

// 	if !inv {
// 		mixedWord, err = c.MixColumns(state)
// 	} else {
// 		mixedWord, err = c.InvMixColumns(state)
// 	}

// 	if err != nil {
// 		return false, "error", err
// 	}

// 	result, desc := CompareBytes(mixedWord, mixedState)
// 	return result, desc, nil
// }

// func RunMixColTest(inv bool) {
// 	testStates, err := ReadTestFile("testvec/states-test.txt")
// 	if err != nil {
// 		panic(err)
// 	}

// 	mixedStates, err := ReadTestFile("testvec/mixedcolstates-test.txt")
// 	if err != nil {
// 		panic(err)
// 	}

// 	if inv {
// 		testStates, mixedStates = mixedStates, testStates
// 	}

// 	fmt.Printf("Status\tCol_num\tDescription\n")

// 	for i, word := range testStates {
// 		ok, desc, err := TestMixCol(word, mixedStates[i], inv)

// 		if err != nil {
// 			panic(err)
// 		}

// 		fmt.Printf("%v\t%v\t%v\n", map[bool]string{true: "Passed", false: "Failed"}[ok], i, desc)
// 	}
// }

// func TestBlockEncryption(testKey []byte, encVec []byte) (bool, string, error) {
// 	if len(genericPlain) != consts.BLOCK_SIZE {
// 		return false, "test only for one state: len(genericPlain) != BLOCK_SIZE", nil
// 	}

// 	c, err := aes256go.NewAES256(testKey)

// 	if err != nil {
// 		return false, "error", err
// 	}

// 	// The keys have to be reassigned here due to
// 	// key hashing inside NewAES256().
// 	// Otherwise the keys won't match the ones
// 	// saved in test vector files -> test will fail.
// 	// Please don't do this in the actual encryption.
// 	c.Key = testKey
// 	c.ExpandedKey, err = key.ExpandKey(c.Key)
// 	if err != nil {
// 		return false, "error", err
// 	}

// 	state := make([]byte, len(genericPlain))
// 	copy(state, genericPlain)

// 	encryptedBlock, err := c.EncryptBlock(state)

// 	if err != nil {
// 		return false, "error", err
// 	}

// 	result, desc := CompareBytes(encryptedBlock, encVec)
// 	return result, desc, nil
// }

// func RunBlockEncryptionTest() {
// 	keys, err := ReadTestFile("testvec/blockkey-test.txt")
// 	if err != nil {
// 		panic(err)
// 	}

// 	ciphers, err := ReadTestFile("testvec/blockenc-test.txt")
// 	if err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("Status\tState_num\tDescription\n")

// 	for i, k := range keys {
// 		ok, desc, err := TestBlockEncryption(k, ciphers[i])

// 		if err != nil {
// 			panic(err)
// 		}

// 		fmt.Printf("%v\t%v\t%v\n", map[bool]string{true: "Passed", false: "Failed"}[ok], i, desc)
// 	}
// }

// func TestBlockDecryption(testKey []byte, cipher []byte) (bool, string, error) {
// 	if len(genericPlain) != consts.BLOCK_SIZE {
// 		return false, "test only for one state: len(genericPlain) != BLOCK_SIZE", nil
// 	}

// 	c, err := aes256go.NewAES256(testKey)

// 	if err != nil {
// 		return false, "error", err
// 	}

// 	// The keys have to be reassigned here due to
// 	// key hashing inside NewAES256().
// 	// Otherwise the keys won't match the ones
// 	// saved in test vector files -> test will fail.
// 	// Please don't do this in the actual encryption.
// 	c.Key = testKey
// 	c.ExpandedKey, err = key.ExpandKey(c.Key)
// 	if err != nil {
// 		return false, "error", err
// 	}

// 	state := make([]byte, len(cipher))
// 	copy(state, cipher)

// 	decryptedBlock, err := c.DecryptBlock(state)

// 	if err != nil {
// 		return false, "error", err
// 	}

// 	result, desc := CompareBytes(decryptedBlock, genericPlain)
// 	return result, desc, nil
// }

// func RunBlockDecryptionTest() {
// 	keys, err := ReadTestFile("testvec/blockkey-test.txt")
// 	if err != nil {
// 		panic(err)
// 	}

// 	ciphers, err := ReadTestFile("testvec/blockenc-test.txt")
// 	if err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("Status\tState_num\tDescription\n")

// 	for i, k := range keys {
// 		ok, desc, err := TestBlockDecryption(k, ciphers[i])

// 		if err != nil {
// 			panic(err)
// 		}

// 		fmt.Printf("%v\t%v\t%v\n", map[bool]string{true: "Passed", false: "Failed"}[ok], i, desc)
// 	}
// }

func main() {
	// MOST OF THE TEST ARE DEPRICATED DUE TO CHANGING MOST METHODS TO BE PRIVATE
	//
	// Watch out for large output.
	// Highly recommend running one
	// test at a time and directing
	// it to a file.
	//
	// $ go run test-all.go > tests.txt

	RunKeyTest()
	fmt.Println()
	// RunMixColTest(false)
	// fmt.Println()
	// RunMixColTest(true)
	// fmt.Println()
	// RunBlockEncryptionTest()
	// fmt.Println()
	// RunBlockDecryptionTest()
	// fmt.Println()
}
