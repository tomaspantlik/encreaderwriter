package encreaderwriter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	verMajor uint16 = 1
	verMinor uint16 = 1
	verPatch uint16 = 0
	magic           = "encreaderwriter"
)

/*
writer:
- header:
	- string("encreaderwriter")
	- uint16(version_major)
	- uint16(version_minor)
	- uint16(version_patch)
	- uint64(length of encrypted AES key)
	- []byte(encrypted AES key)
- message:
	- uint64(length of nonce)
	- []byte(nonce)
	- uint64(length of encrypted data)
	- []byte(encrypted data)
*/

type EncrypWriter struct {
	gcm    cipher.AEAD
	writer io.Writer
}

// TODO: proper tests
// TODO: documentation

func writeHeader(writer io.Writer) error {
	if _, err := writer.Write([]byte(magic)); err != nil {
		return err
	}

	err := binary.Write(writer, binary.LittleEndian, verMajor)
	if err != nil {
		return err
	}

	err = binary.Write(writer, binary.LittleEndian, verMinor)
	if err != nil {
		return err
	}

	err = binary.Write(writer, binary.LittleEndian, verPatch)
	if err != nil {
		return err
	}

	return nil
}

func checkHeader(reader io.Reader) error {
	var m = make([]byte, len(magic))
	if _, err := reader.Read(m); err != nil {
		return err
	}
	if string(m) != magic {
		return fmt.Errorf("missing magic header")
	}

	var major uint16
	if err := binary.Read(reader, binary.LittleEndian, &major); err != nil {
		return err
	} else {
		if major != verMajor {
			return fmt.Errorf("major version (%d) != %d", major, verMajor)
		}
	}

	var minor uint16
	if err := binary.Read(reader, binary.LittleEndian, &minor); err != nil {
		return err
	} else {
		if minor != verMinor {
			return fmt.Errorf("minor version (%d) != %d", minor, verMinor)
		}
	}

	var patch uint16
	if err := binary.Read(reader, binary.LittleEndian, &patch); err != nil {
		return err
	} else {
		if patch != verPatch {
			return fmt.Errorf("patch version (%d) != %d", patch, verPatch)
		}
	}

	return nil
}

/*
OpenEncryptWriter() opens EncryptWriter with underlying io.Writer and writes
encrypted AES key for data encryption
*/
func OpenEncryptWriter(pubKey *rsa.PublicKey, writer io.Writer) (ew EncrypWriter, err error) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return EncrypWriter{}, fmt.Errorf("error generating AES key: %w", err)
	}

	encryptedAESKey, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader, pubKey, aesKey, nil,
	)
	if err != nil {
		return EncrypWriter{}, fmt.Errorf("rsa.EncryptOAEP(): %w", err)
	}

	if err := writeHeader(writer); err != nil {
		return ew, fmt.Errorf("error writing header: %w", err)
	}

	err = binary.Write(writer, binary.LittleEndian, uint64(len(encryptedAESKey)))
	if err != nil {
		return EncrypWriter{}, fmt.Errorf("error writing AES key: %w", err)
	}

	if _, err := writer.Write(encryptedAESKey); err != nil {
		return EncrypWriter{}, fmt.Errorf("error writing AES key: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return EncrypWriter{}, fmt.Errorf("aes.NewCipher(): %w", err)
	}

	ew.gcm, err = cipher.NewGCM(block)
	if err != nil {
		return EncrypWriter{}, fmt.Errorf("aes.NewGCM(): %w", err)
	}

	ew.writer = writer

	return ew, nil
}

/*
Write() implements io.Writer interface for writing encrypted data to underlying io.Writer
*/
func (ew EncrypWriter) Write(data []byte) (n int, err error) {
	nonce := make([]byte, ew.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, fmt.Errorf("error generating nonce: %w", err)
	}

	err = binary.Write(ew.writer, binary.LittleEndian, uint64(len(nonce)))
	if err != nil {
		return 0, err
	}

	if _, err := ew.writer.Write(nonce); err != nil {
		return 0, err
	}

	encrypted := ew.gcm.Seal(nil, nonce, data, nil)

	err = binary.Write(ew.writer, binary.LittleEndian, uint64(len(encrypted)))
	if err != nil {
		return 0, err
	}

	return ew.writer.Write(encrypted)
}

type Decryptor struct {
	gcm    cipher.AEAD
	reader io.Reader
}

/*
OpenDecryptor() opens Decryptor from undrylying io.Reader for reading whole messages
*/
func OpenDecryptor(key *rsa.PrivateKey, reader io.Reader) (d Decryptor, err error) {
	if err := checkHeader(reader); err != nil {
		return Decryptor{}, fmt.Errorf("error opening file: %w", err)
	}

	var keyLength uint64
	if err := binary.Read(reader, binary.LittleEndian, &keyLength); err != nil {
		return Decryptor{}, fmt.Errorf("error reading encrypted AES key: %w", err)
	}

	encryptedKey := make([]byte, keyLength)
	if _, err := reader.Read(encryptedKey); err != nil {
		return Decryptor{}, fmt.Errorf("error reading encrypted AES key: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encryptedKey, nil)
	if err != nil {
		return Decryptor{}, fmt.Errorf("rsa.DecryptOAEP(): %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return Decryptor{}, fmt.Errorf("aes.NewCipher(): %w", err)
	}

	d.gcm, err = cipher.NewGCM(block)
	if err != nil {
		return Decryptor{}, fmt.Errorf("aes.NewGCM(): %w", err)
	}

	d.reader = reader

	return d, nil
}

/*
ReadMsg() reads and decrypt whole message from underlying encrypted io.Reader
*/
func (dr Decryptor) ReadMsg() (decrypted []byte, err error) {
	var nonceLength uint64
	if err := binary.Read(dr.reader, binary.LittleEndian, &nonceLength); err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLength)
	if _, err := dr.reader.Read(nonce); err != nil {
		return nil, err
	}

	var dataLength uint64
	if err := binary.Read(dr.reader, binary.LittleEndian, &dataLength); err != nil {
		return nil, err
	}
	data := make([]byte, dataLength)
	if _, err := dr.reader.Read(data); err != nil {
		return nil, err
	}

	decrypted, err = dr.gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm.Open(): %w", err)
	}

	return decrypted, nil
}

type DecryptReader struct {
	Decryptor
	buf    []byte
	offset int
	eof    bool
}

/*
OpenDecryptReader() opens DecryptorReader from undrylying io.Reader for reading by io.Reader interface
*/
func OpenDecryptReader(key *rsa.PrivateKey, reader io.Reader) (dr *DecryptReader, err error) {
	dr = &DecryptReader{}

	dr.Decryptor, err = OpenDecryptor(key, reader)
	if err != nil {
		return &DecryptReader{}, err
	}

	dr.buf, err = dr.ReadMsg()
	if err != nil {
		return &DecryptReader{}, err
	}

	return dr, nil
}

/*
Read() implements io.Reader interface for reading encrypted data from underlying io.Reader
*/
func (dr *DecryptReader) Read(p []byte) (n int, err error) {
	if dr.eof {
		return 0, io.EOF
	}

	var ni int
	for {
		ni = copy(p[n:], (dr.buf)[dr.offset:])
		n += ni
		dr.offset = ni
		if n == len(p) {
			break
		}

		dr.offset = 0
		dr.buf, err = dr.ReadMsg()
		if err != nil {
			if err == io.EOF {
				dr.eof = true
			}
			return n, err
		}
	}

	return n, nil
}
