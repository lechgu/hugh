package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"

	"golang.org/x/crypto/ssh"
)

// Encrypt ...
func Encrypt(reader io.Reader, pubKeyReader io.Reader) ([]byte, error) {
	pubKey, err := importPubKey(pubKeyReader)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(reader)
	if err != nil {
		return nil, err
	}
	return fullEncrypt(buf.Bytes(), pubKey)
}

// Decrypt ...
func Decrypt(encReader io.Reader, privKeyReader io.Reader) ([]byte, error) {
	privKey, err := importPrivKey(privKeyReader)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(encReader)
	if err != nil {
		return nil, err
	}
	return fullDecrypt(buf.Bytes(), privKey)
}

func importPrivKey(r io.Reader) (*rsa.PrivateKey, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}
	privPem, _ := pem.Decode(buf.Bytes())
	privKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func importPubKey(r io.Reader) (*rsa.PublicKey, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(buf.Bytes())
	if err != nil {
		return nil, err
	}
	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)
	pubCrypto := parsedCryptoKey.CryptoPublicKey()
	pub := pubCrypto.(*rsa.PublicKey)
	return pub, nil

}

func generateSessionKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	return key, err
}

func encryptSessionKey(data []byte, key *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, nil)
}

func decryptSessionKey(data []byte, key *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, key, data, nil)
}

func symmetricEncrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, data, nil), nil
}

func symmetricDecrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, data, nil)
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func fullEncrypt(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	sessionKey, err := generateSessionKey()
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	encData, err := symmetricEncrypt(data, sessionKey, nonce)
	if err != nil {
		return nil, err
	}
	encSessionKey, err := encryptSessionKey(sessionKey, publicKey)
	if err != nil {
		return nil, err
	}
	eskLen := len(encSessionKey)
	nonceLen := len(nonce)
	encDataLen := len(encData)
	ct := make([]byte, eskLen+nonceLen+encDataLen)
	copy(ct, encSessionKey)
	copy(ct[eskLen:], nonce)
	copy(ct[eskLen+nonceLen:], encData)
	return ct, nil
}

func fullDecrypt(data []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	keyLen := len(privKey.D.Bytes())
	encSessionKey := data[:keyLen]
	nonce := data[keyLen : keyLen+12]
	encData := data[keyLen+12:]
	sessionKey, err := decryptSessionKey(encSessionKey, privKey)
	if err != nil {
		return nil, err
	}
	return symmetricDecrypt(encData, sessionKey, nonce)
}
