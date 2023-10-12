package services

import (
	"bytes"
	"encoding/base64"
	"io"
	"io/ioutil"

	"filippo.io/age"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

type AgeService struct {
	identity  *age.X25519Identity
	publicKey string
}

func NewAgeService(privateKey string, publickey string) (*AgeService, error) {

	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, err
	}
	l, _ := zap.NewDevelopment()
	logger := l.Sugar()
	defer logger.Sync()
	return &AgeService{
		identity:  identity,
		publicKey: publickey,
	}, nil
}

func (a *AgeService) Encrypt(text string) (string, error) {
	recipient := a.identity.Recipient()
	buffer := bytes.NewBufferString(text)
	var encryptedBuf bytes.Buffer
	encrypted, err := age.Encrypt(&encryptedBuf, recipient)
	if err != nil {
		logger.Errorf("Failed to encrypt the text")
		return "", err
	}
	if _, err := io.Copy(encrypted, buffer); err != nil {
		logger.Errorf("Failed to copy data to encrypted writer")
		return "", err
	}
	if err := encrypted.Close(); err != nil {
		logger.Errorf("Failed to close encrypted writer")
		return "", err
	}
	return encryptedBuf.String(), nil
}

func (a *AgeService) EncryptAndEncode(text string) (string, error) {
	encrypt, err := a.Encrypt(text)
	if err != nil {
		logger.Errorf("Could not encrypt text")
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(encrypt)), nil
}

func (a *AgeService) Decrypt(encryptedText string) (string, error) {
	encryptedBuf := bytes.NewBufferString(encryptedText)

	decrypted, err := age.Decrypt(encryptedBuf, a.identity)
	if err != nil {
		logger.Errorf("Failed to decrypt the text")
		return "", err
	}

	decryptedBytes, err := ioutil.ReadAll(decrypted)
	if err != nil {
		logger.Errorf("Failed to read decrypted data")
		return "", err
	}

	return string(decryptedBytes), nil
}

func (a *AgeService) DecryptAndDecode(encryptedText string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		logger.Errorf("Could not decode encrypted text")
		return "", err
	}
	decrypted, err := a.Decrypt(string(decoded[:]))
	if err != nil {
		logger.Errorf("Could not decrypt text")
		return "", err
	}

	return decrypted, nil
}
