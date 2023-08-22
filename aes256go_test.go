package aes256go

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

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

	var keyExpansionTest = []struct {
		testKey             []byte
		expectedExpandedKey []byte
	}{}

	for i, key := range testKeys {
		keyExpansionTest = append(keyExpansionTest,
			struct {
				testKey             []byte
				expectedExpandedKey []byte
			}{key, testExpandedKeys[i]},
		)
	}

	for _, test := range keyExpansionTest {
		expandedKey, err := key.ExpandKey(test.testKey)
		if err != nil {
			t.Error(err)
		}

		actualExpandedKey := make([]byte, len(expandedKey))
		copy(actualExpandedKey, expandedKey[:])

		if !bytes.Equal(actualExpandedKey, test.expectedExpandedKey) {
			t.Fatalf("FAILED: key expansion test failed")
		}
	}
}
