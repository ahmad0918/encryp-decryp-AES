package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

func main() {
	plaintext := "EAAFtLTmtn9oBO2RaEIuryw2eiiFx0YOu7HUnu9Ks7dJCvCnOe9XpjIN6iauu6snfyRvsHUtp7KSAW1jkwcRRJeEDHacl7aaLBKvtzGZBiIzvSh8sfrCQAAWcL2ZAmDYkvEz0Gy4lZA5b7TXprkbZCxUXwvWZBt6Rd1hJnkK5cCZBdXRY1jvs8ex5Ss8MkWh8gP"
	key := "RUUzMzU1MUZDNDdBQ0JGODMzM0UzNDRD"

	encrypt := encryptAES(key, plaintext)
	decrypt := decryptAES(key, encrypt)

	fmt.Println("Original Text : ", plaintext)
	fmt.Println("Encrypted Text : ", encrypt)
	fmt.Println("Decrypted Text : ", decrypt)
}

func decryptAES(key string, value string) string {
	cipherText, err := hex.DecodeString(value)
	if err != nil {
		log.Println("Error decoding hex:", err)
		return ""
	}

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Println("Error creating cipher:", err)
		return ""
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("Error creating GCM:", err)
		return ""
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		log.Println("CipherText is too short")
		return ""
	}

	nonce, ciphertext := cipherText[:nonceSize], cipherText[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println("Error decrypting:", err)
		return ""
	}

	return string(plaintext)
}

func encryptAES(key string, plaintext string) string {
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Println("Error creating cipher:", err)
		return ""
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("Error creating GCM:", err)
		return ""
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println("Error creating nonce:", err)
		return ""
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext)
}
