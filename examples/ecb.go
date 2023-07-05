package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
	"github.com/wedkarz02/aes256go/src/padding"
)

// This is an example usage of ECB mode encryption.
func EncryptECBExample(key []byte, plainText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText using ECB mode.
	// Padding can either be ZeroPadding or PKCS7Padding.
	cipherText, err := cipher.EncryptECB(plainText, padding.ZeroPadding)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherText
}

// This is an example usage of ECB mode decryption.
func DecryptECBExample(key []byte, cipherText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText using ECB mode.
	// Padding can either be ZeroPadding or PKCS7Padding.
	// Make sure that the padding is the same for encryption and decryption.
	plainText, err := cipher.DecryptECB(cipherText, padding.ZeroUnpadding)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Decryption error: %v\n", err)
	}

	return plainText
}
