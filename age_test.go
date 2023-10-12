package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func createTestAgeService(t *testing.T) *AgeService {
	publicKey := "age137jhzqt58vjpwmjak50zgp0slrwdudrenjwcwthnrttfpmdk9djqvrq49z"
	privateKey := "AGE-SECRET-KEY-14WRK2CASH2828FM6W0TJ83QAV3XCT3RVP0VPG9F7M2KJAEAW444SECCP4A"
	ageService, err := NewAgeService(privateKey, publicKey)
	if err != nil {
		t.Fatalf("Failed to create AgeService: %v", err)
	}
	return ageService
}

func TestAgeServiceEncryptDecryptLongPassword(t *testing.T) {
	ageService := createTestAgeService(t)

	password := "thisisaverylongpasswordthisisaverylongpasswordthisisaverylongpassword"

	encrypted, err := ageService.Encrypt(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := ageService.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, password, decrypted)
}

func TestAgeServiceEncryptDecryptMediumPassword(t *testing.T) {
	ageService := createTestAgeService(t)

	password := "mediumpassword12345678##!!2$$''''90"

	encrypted, err := ageService.Encrypt(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := ageService.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, password, decrypted)
}

func TestAgeServiceEncryptDecryptShortPassword(t *testing.T) {
	ageService := createTestAgeService(t)

	password := "shortpass###sada213123#"

	encrypted, err := ageService.Encrypt(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := ageService.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, password, decrypted)
}

func TestAgeServiceEncryptDecode(t *testing.T) {
	ageService := createTestAgeService(t)

	password := "shortpass###sada213123#"

	encrypted, err := ageService.EncryptAndEncode(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	decrypted, err := ageService.DecryptAndDecode(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, password, decrypted)
}
