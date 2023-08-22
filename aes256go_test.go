package aes256go

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/wedkarz02/aes256go/src/consts"
	"github.com/wedkarz02/aes256go/src/key"
)

func readTestFile(fileName string) ([][]byte, error) {
	file, err := os.Open(fileName)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var testData [][]byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		data := strings.Split(scanner.Text(), " ")
		keyStr := strings.Join(data, "")

		bytes, err := hex.DecodeString(keyStr)
		if err != nil {
			fmt.Println(hex.EncodeToString(bytes))
			return nil, err
		}

		testData = append(testData, bytes)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return testData, nil
}

func TestExpandKey(t *testing.T) {
	testKeys, err := readTestFile("test/testvec/keyvec-test.txt")
	if err != nil {
		panic(err)
	}

	testExpandedKeys, err := readTestFile("test/testvec/xkeyvec-test.txt")
	if err != nil {
		panic(err)
	}

	if len(testKeys) != len(testExpandedKeys) {
		panic("test len error")
	}

	for i, testKey := range testKeys {
		expandedKey, err := key.ExpandKey(testKey)
		if err != nil {
			t.Error(err)
		}

		actualExpandedKey := make([]byte, len(expandedKey))
		copy(actualExpandedKey, expandedKey[:])

		if !reflect.DeepEqual(actualExpandedKey, testExpandedKeys[i]) {
			t.Fatalf("FAILED: key expansion test failed")
		}
	}
}

func TestEncryptBlock(t *testing.T) {
	testKeys, err := readTestFile("test/testvec/blockkey-test.txt")
	if err != nil {
		panic(err)
	}

	expectedStates, err := readTestFile("test/testvec/blockenc-test.txt")
	if err != nil {
		panic(err)
	}

	if len(testKeys) != len(expectedStates) {
		panic("test len error")
	}

	zeroState := make([]byte, consts.BLOCK_SIZE)

	for i, testKey := range testKeys {
		a, err := NewAES256(testKey)
		if err != nil {
			panic(err)
		}

		// The keys have to be reassigned here due to
		// key hashing inside NewAES256().
		// Otherwise the keys won't match the ones
		// saved in test vector files -> test will fail.
		// Please don't do this in the actual encryption.
		a.Key = testKey
		a.expandedKey, err = key.ExpandKey(a.Key)
		if err != nil {
			panic(err)
		}

		actualState, err := a.EncryptBlock(zeroState)
		if err != nil {
			panic(err)
		}

		if !reflect.DeepEqual(actualState, expectedStates[i]) {
			t.Fatalf("FAILED: block encryption failed")
		}
	}
}

func TestDecryptBlock(t *testing.T) {
	testKeys, err := readTestFile("test/testvec/blockkey-test.txt")
	if err != nil {
		panic(err)
	}

	encryptedStates, err := readTestFile("test/testvec/blockenc-test.txt")
	if err != nil {
		panic(err)
	}

	if len(testKeys) != len(encryptedStates) {
		panic("test len error")
	}

	expectedZeroState := make([]byte, consts.BLOCK_SIZE)

	for i, testKey := range testKeys {
		a, err := NewAES256(testKey)
		if err != nil {
			panic(err)
		}

		// The keys have to be reassigned here due to
		// key hashing inside NewAES256().
		// Otherwise the keys won't match the ones
		// saved in test vector files -> test will fail.
		// Please don't do this in the actual encryption.
		a.Key = testKey
		a.expandedKey, err = key.ExpandKey(a.Key)
		if err != nil {
			panic(err)
		}

		actualState, err := a.DecryptBlock(encryptedStates[i])
		if err != nil {
			panic(err)
		}

		if !reflect.DeepEqual(actualState, expectedZeroState) {
			t.Fatalf("FAILED: block decryption failed")
		}
	}
}
