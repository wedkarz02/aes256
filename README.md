# AES256

[![Go Reference](https://pkg.go.dev/badge/github.com/wedkarz02/aes256go.svg)](https://pkg.go.dev/github.com/wedkarz02/aes256go)
[![Go Report Card](https://goreportcard.com/badge/github.com/wedkarz02/aes256go)](https://goreportcard.com/report/github.com/wedkarz02/aes256go)
![GitHub release (with filter)](https://img.shields.io/github/v/release/wedkarz02/aes256go)
[![GitHub](https://img.shields.io/github/license/wedkarz02/aes256go)](https://github.com/wedkarz02/aes256go/blob/main/LICENSE)

Go implementation of 256 bit version of the Advanced Encryption Standard algorithm. It is tested with [test vectors provided by NIST](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf), among some others, to make sure that the implementation is correct. \
Current version provides access to raw block encryption as well as these modes of operation:
 * ECB - Electronic Code Book
 * CBC - Cipher Block Chaining
 * CFB - Cipher Feedback
 * OFB - Output Feedback
 * CTR - Counter Mode
 * GCM - Galois Counter Mode

As always, I do not recommend using this package for anything that needs actual security.

# Requirements
 * [Go v1.20+](https://go.dev/dl/)
 * [Linux OS (preferably)](https://ubuntu.com/download)

# Quick Setup
If you haven't created a go module for your project, you can do that with the ``go mod`` command:
```bash
$ go mod init [project name]
```
To include this package in your project use the ``go get`` command:
```bash
$ go get -u github.com/wedkarz02/aes256go
```

# Example
```go
// main.go
package main

import (
    "fmt"
    "log"

    "github.com/wedkarz02/aes256go"
    "github.com/wedkarz02/aes256go/src/padding"
)

func main() {
    key := []byte("Top secret key")
    message := []byte("Hey, new Shrek movie coming out soon (hopefully...)")

    // Cipher object initialization.
    cipher, err := aes256go.NewAES256(key)

    // It is strongly recommended to wipe the key from memory at the end.
    defer cipher.ClearKey()

    // Make sure to check for any errors.
    if err != nil {
        log.Fatalf("Cipher init error: %v\n", err)
    }

    // Encrypting the plainText using CBC mode.
    // Padding can either be ZeroPadding or PKCS7Padding.
    cipherText, err := cipher.EncryptCBC(message, padding.PKCS7Padding)

    // Make sure to check for any errors.
    if err != nil {
        log.Fatalf("Encryption error: %v\n", err)
    }

    // Printing the cipherText as bytes.
    for _, b := range cipherText {
        fmt.Printf("0x%02x ", b)
    }
}
```

You might also need to use the ``go mod tidy`` command to fetch necessary dependencies:
```bash
$ go mod tidy
```

For more examples, see [aes256go/examples](https://github.com/wedkarz02/aes256go/tree/main/examples).

# Testing
To test this package use the ``go test`` command from the root directory:
```bash
$ go test -v
```

# Documentation
For more documentation, see [pkg.go.dev](https://pkg.go.dev/github.com/wedkarz02/aes256go).

# License
aes256go is available under the MIT license. See the [LICENSE](https://github.com/wedkarz02/aes256go/blob/main/LICENSE) file for more info.
