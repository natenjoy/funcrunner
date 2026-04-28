package netauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"os"
	"time"
)

// Encrypt takes plaindata and key and produces cipherbytes
func Encrypt(key, plaindata []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	cipherbytes := gcm.Seal(nonce, nonce, plaindata, nil)

	return cipherbytes, nil
}

// Decrypt takes cipherdata and returns plainbytes with key
func Decrypt(key, cipherdata []byte) ([]byte, error) {
	if len(cipherdata) < 12 {
                e := fmt.Errorf("user encryption error. try removing ~/.creds.enc file")
                return nil, e
        }

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	nonce, cipherbytes := cipherdata[:gcm.NonceSize()], cipherdata[gcm.NonceSize():]

	plainbytes, err := gcm.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return nil, err
	}

	return plainbytes, nil
}

// GetSymmetricKeyFromFile loads a key from file
func GetSymmetricKeyFromFile(fname string) []byte {
	key, err := ioutil.ReadFile(fname)
	if err != nil {
		e := fmt.Sprintf("Error obtaining key from file %s: %s", fname, err)
		log.Fatalf(e)
	}
	return key
}

// CreateNewSymmetricKeyFile saves a key to fname
func CreateNewSymmetricKeyFile(fname string, key []byte) error {
	if len(key) != 32 {
		e := fmt.Errorf("Invalid key. Key length must be 32 bytes")
		return e
	}
	err := ioutil.WriteFile(fname, key, os.FileMode(int(0777)))
	if err != nil {
		e := fmt.Errorf("Could not save key to %s: %s", fname, err)
		return e
	}
	return nil
}

// EncryptToFile encrypts plainbytes with key and saves to fname
func EncryptToFile(key, plainbytes []byte, fname string) error {
	cipherbytes, err := Encrypt(key, plainbytes)
	if err != nil {
		e := fmt.Errorf("Encryption error: %s", err)
		return e
	}

	err = ioutil.WriteFile(fname, cipherbytes, os.FileMode(int(0777)))
	if err != nil {
		e := fmt.Errorf("Error writing to file: %s", err)
		return e
	}
	return nil
}

// DecryptFromFile decrypts fname with key and returns the file bytes
func DecryptFromFile(key []byte, fname string) ([]byte, error) {
	cipherbytes, err := ioutil.ReadFile(fname)
	if err != nil {
		e := fmt.Errorf("Error opening file: %s", err)
		return nil, e
	}

	plainbytes, err := Decrypt(key, cipherbytes)
	if err != nil {
		e := fmt.Errorf("Decryption error: %s", err)
		return nil, e
	}
	return plainbytes, nil
}

// GenRandomKey generates and returns a random 32 byte key
func GenRandomKey() []byte {
	key := make([]byte, 32)
	mrand.Seed(time.Now().UnixNano())
	mrand.Read(key)
	return key
}
