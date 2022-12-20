package chacha20poly1305_scrypt_block

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

type Params struct {
	SaltSize  int
	NonceSize int
	KeySize   int
	Key       []byte
}

// Sane defaults
var ParamDefaults = Params{
	SaltSize:  32,
	NonceSize: chacha20poly1305.NonceSizeX,
	KeySize:   chacha20poly1305.KeySize,
}

// Encrypt function based on chacha20poly1305 and scrypt
func (c *Params) Encrypt(data []byte) ([]byte, error) {
	// Check if key is long enough
	if len(c.Key) < c.KeySize {
		return nil, fmt.Errorf("key is too short, expecting %d bytes", c.KeySize)
	}

	// Check if data is bigger than Uint32
	if uint32(len(data)) > ^uint32(0) {
		return nil, fmt.Errorf("data chunk is too big, max size is : %d bytes", ^uint32(0))
	}

	keySalt := make([]byte, c.SaltSize)
	if _, err := rand.Read(keySalt); err != nil {
		return nil, err
	}

	hashedKey, err := scrypt.Key([]byte(c.Key[:c.KeySize]), keySalt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	chunk := make([]byte, 0)
	aead, _ := chacha20poly1305.NewX(hashedKey[:])
	nonce := make([]byte, c.NonceSize)

	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	chunk = append(chunk, nonce...)
	chunk = append(chunk, keySalt...)
	chunk = append(chunk, aead.Seal(nil, nonce, data, nil)...)

	// Calculate chunkSize of chunk and Prepend chunkSize to chunk
	chunkSize := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkSize, uint32(len(chunk[:])))
	// Prepends chunkSize to chunk
	chunk = append(chunkSize, chunk...)

	return chunk, nil
}

// Decrypt function based on chacha20poly1305 and scrypt
func (c *Params) Decrypt(data []byte) ([]byte, error) {
	// Check if key is long enough
	if len(c.Key) < c.KeySize {
		return nil, fmt.Errorf("key is too short, expecting %d bytes", c.KeySize)
	}

	chunkSize := binary.BigEndian.Uint32(data[:4])
	if uint32(len(data[4:])) != chunkSize {
		return nil, io.ErrUnexpectedEOF
	}
	nonce := data[4 : 4+c.NonceSize]
	keySalt := data[4+c.NonceSize : 4+c.NonceSize+c.SaltSize]
	hashedKey, err := scrypt.Key([]byte(c.Key[:c.KeySize]), keySalt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	aead, _ := chacha20poly1305.NewX(hashedKey[:])
	decrypted, err := aead.Open(nil, nonce, data[4+c.NonceSize+c.SaltSize:], nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func Init(params Params) (*Params, error) {
	// Go over all params and if unset set them to defaults
	if params.SaltSize == 0 {
		params.SaltSize = ParamDefaults.SaltSize
	}

	if params.NonceSize == 0 {
		params.NonceSize = ParamDefaults.NonceSize
	}

	if params.KeySize == 0 {
		params.KeySize = ParamDefaults.KeySize
	}

	// Return error if key is not set
	if params.Key == nil {
		return nil, fmt.Errorf("key is not set")
	}

	return &params, nil
}
