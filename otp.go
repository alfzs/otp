package otp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNotFound    = errors.New("otp not found or expired")
	ErrInvalidCode = errors.New("invalid otp code")
)

// Storage OTP кодов
type Storage interface {
	Get(ctx context.Context, tenantID uuid.UUID, requestID, phone string) ([]byte, bool, error)
	Delete(ctx context.Context, tenantID uuid.UUID, requestID, phone string) error
	Set(ctx context.Context, tenantID uuid.UUID, requestID, phone string, value []byte, ttl time.Duration) error
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

type CreateParams struct {
	TenantID  uuid.UUID
	RequestID string
	Phone     string
	Secret    string
}

// Create генерирует и сохраняет OTP
func (m *OTPManager) Create(ctx context.Context, p CreateParams) (string, error) {
	plainOTP, err := generate(m.lengthOTP)
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	hashOTP, err := bcrypt.GenerateFromPassword([]byte(plainOTP), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash otp: %w", err)
	}

	if err := m.storage.Set(ctx, p.TenantID, p.RequestID, p.Phone, hashOTP, m.cacheTTL); err != nil {
		return "", fmt.Errorf("store otp: %w", err)
	}

	encryptedOTP, err := encrypt(p.Secret, p.RequestID, p.Phone, plainOTP)
	if err != nil {
		return "", fmt.Errorf("encrypt otp: %w", err)
	}

	return encryptedOTP, nil
}

type VerifyParams struct {
	TenantID  uuid.UUID
	RequestID string
	Phone     string
	Code      string
}

// Verify — одноразовая проверка OTP
func (m *OTPManager) Verify(ctx context.Context, p VerifyParams) error {
	// Получаем OTP код из хранилища
	hash, ok, err := m.storage.Get(ctx, p.TenantID, p.RequestID, p.Phone)
	if err != nil {
		return fmt.Errorf("get otp: %w", err)
	}
	if !ok {
		return ErrNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(p.Code)); err != nil {
		// код неверный, не трогаем storage
		return ErrInvalidCode
	}

	// При успехе удаляем OTP из хранилища
	if err := m.storage.Delete(ctx, p.TenantID, p.RequestID, p.Phone); err != nil {
		return fmt.Errorf("delete otp: %w", err)
	}

	return nil
}

type DecryptParams struct {
	RequestID string
	Phone     string
	Secret    string
	Encrypted string
}

// Decrypt — расшифровка OTP
func Decrypt(p DecryptParams) (string, error) {
	key := deriveAESKey(p.Secret)

	data, err := base64.StdEncoding.DecodeString(p.Encrypted)
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
	aadHash := sha256.Sum256([]byte(p.RequestID + ":" + p.Phone))

	plain, err := gcm.Open(nil, nonce, ciphertext, aadHash[:])
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
