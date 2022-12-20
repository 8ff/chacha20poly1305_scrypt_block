# Simple wrapper around chacha20poly1305 and scrypt
Simple wrapper around the chacha20poly1305 and scrypt hash to encrypt small chunks of data.<br>
For stream variant see [https://github.com/8ff/chacha20poly1305_scrypt_stream](https://github.com/8ff/chacha20poly1305_scrypt_stream).<br>
Can be used as a library or as a command line tool located in [cmd/cipherCli](cmd/cipherCli).

## Library usage
```golang
package main

import (
	"bytes"
	"log"

	cipher "github.com/8ff/chacha20poly1305_scrypt_block"
)

func main() {
	data := []byte("Hello world")
	key := make([]byte, cipher.ParamDefaults.KeySize)
	// Set key to some long phrase that is of key size
	copy(key, []byte("This is a long phrase that is of key size"))

	// Initialize cipher
	c, err := cipher.Init(cipher.Params{Key: key})
	if err != nil {
		log.Fatalf("Failed to initialize cipher: %v", err)
	}

	// Encrypt data
	encrypted, err := c.Encrypt(data)
	if err != nil {
		log.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt data
	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		log.Fatalf("Failed to decrypt data: %v", err)
	}

	// Verify that decrypted data is the same as original data
	if !bytes.Equal(data, decrypted) {
		log.Fatalf("Decrypted data is not the same as original data")
	}

	// Print Input and decrypted string
	log.Printf("Input: %s\n", data)
	log.Printf("Decrypted: %s\n", decrypted)
}
```

## Command line usage
```bash
foo@bar:~$ cd cmd/cipherCli
foo@bar:~$ cipherCli % echo test | CKEY=test go run cipherCli.go e | CKEY=test go run cipherCli.go d
test
```


## Disclaimer
This is a very simple wrapper around the chacha20poly1305 and scrypt hash.
It has not been audited, use at your own risk.