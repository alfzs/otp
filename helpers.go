package otp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// generate формирует криптографически стойкий числовой OTP
func generate(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid otp length: %d", length)
	}

	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	format := fmt.Sprintf("%%0%dd", length)
	return fmt.Sprintf(format, n), nil
}

// encrypt — AES-GCM с AAD
func encrypt(secret, requestID, phone, plain string) (string, error) {
	key := deriveAESKey(secret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	aad := sha256.Sum256([]byte(requestID + ":" + phone))
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), aad[:])

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func deriveAESKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
