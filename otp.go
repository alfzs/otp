package otp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound    = errors.New("otp not found or expired")
	ErrInvalidCode = errors.New("invalid otp code")
)

// Storage OTP кодов
type Storage interface {
	Get(ctx context.Context, requestID, phone string) ([]byte, bool, error)
	Delete(ctx context.Context, requestID, phone string) error
	Set(ctx context.Context, requestID, phone string, value []byte, ttl time.Duration) error
}

type OTPManager struct {
	storage   Storage
	lengthOTP int
	cacheTTL  time.Duration
}

type Params struct {
	Storage   Storage
	LengthOTP int
	CacheTTL  time.Duration
}

func NewOTPManager(p Params) *OTPManager {
	if p.CacheTTL == 0 {
		p.CacheTTL = 3 * time.Minute
	}
	if p.LengthOTP == 0 {
		p.LengthOTP = 6
	}

	return &OTPManager{
		storage:   p.Storage,
		lengthOTP: p.LengthOTP,
		cacheTTL:  p.CacheTTL,
	}
}

// Create генерирует и сохраняет OTP
func (m *OTPManager) Create(ctx context.Context, requestID, phone string, otpKey []byte) (string, error) {
	plainOTP, err := generate(m.lengthOTP)
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	hashOTP, err := bcrypt.GenerateFromPassword([]byte(plainOTP), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash otp: %w", err)
	}

	if err := m.storage.Set(ctx, requestID, phone, hashOTP, m.cacheTTL); err != nil {
		return "", fmt.Errorf("store otp: %w", err)
	}

	encryptedOTP, err := encrypt(otpKey, requestID, phone, plainOTP)
	if err != nil {
		return "", fmt.Errorf("encrypt otp: %w", err)
	}

	return encryptedOTP, nil
}

// Verify — одноразовая проверка OTP
func (m *OTPManager) Verify(ctx context.Context, requestID, phone, code string) error {

	// Обработка стремится к фиксированному времени
	start := time.Now()
	defer func() {
		if d := time.Since(start); d < 500*time.Millisecond {
			time.Sleep(500*time.Millisecond - d)
		}
	}()

	// Получаем OTP код из хранилища
	hash, ok, err := m.storage.Get(ctx, requestID, phone)
	if err != nil {
		return fmt.Errorf("get otp: %w", err)
	}
	if !ok {
		return ErrNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)); err != nil {
		// код неверный, не трогаем storage
		return ErrInvalidCode
	}

	// При успехе удаляем OTP из хранилища
	if err := m.storage.Delete(ctx, requestID, phone); err != nil {
		return fmt.Errorf("delete otp: %w", err)
	}

	return nil
}

// Decrypt — расшифровка OTP
func Decrypt(key []byte, requestID, phone, encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	aad := []byte(requestID + ":" + phone)

	plain, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
