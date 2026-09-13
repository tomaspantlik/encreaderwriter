# usage

## generate keys and store in PEM format with password "secretPassword"

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"github.com/youmark/pkcs8"
)

func main() {
    // private key for decryption:
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal("error generating key:", err)
	}

	keyBytes, err := pkcs8.MarshalPrivateKey(key, []byte("secretPassword"), nil)
	if err != nil {
		log.Fatal("error generating key:", err)
	}

	keyBlock := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: keyBytes,
	}
	keyFile, err := os.Create("test.key")
	if err != nil {
		log.Fatal("error generating key:", err)
	}
	if err := pem.Encode(keyFile, keyBlock); err != nil {
		log.Fatal("error generating key:", err)
	}
	keyFile.Close()

    // public key for encryption:
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatal("error generating key:", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pubFile, err := os.Create("test.pem")
	if err != nil {
		log.Fatal("error generating key:", err)
	}
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		log.Fatal("error generating key:", err)
	}
	pubFile.Close()
}
```

## encrypting data
```go
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"

	erw "github.com/tomaspantlik/encreaderwriter"
)

func main() {
	f, err := os.Create("test.encrypted")
	if err != nil {
		log.Fatal("error creating encrypted file", err)
	}

	pb, err := os.ReadFile("test.pem")
	if err != nil {
		log.Fatal("error opening public key:", err)
	}

	block, _ := pem.Decode(pb)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("error opening public key: wrong format")
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal("error opening public key:", err)
	}

	pubKey, ok := pk.(*rsa.PublicKey)
	if !ok {
		log.Fatal("error opening public key: wrong format")
	}

	ew, err := erw.OpenEncryptWriter(pubKey, f)
	if err != nil {
		log.Fatal("error creating encrypted file", err)
	}

	if _, err := ew.Write([]byte("Hello world!\n")); err != nil {
		log.Fatal("error writing encrypted data:", err)
	}
	if _, err := ew.Write([]byte("The time is " + time.Now().String() + "\n")); err != nil {
		log.Fatal("error writing encrypted data:", err)
	}
	if _, err := ew.Write([]byte("Goodbye world!\n")); err != nil {
		log.Fatal("chyba při zápisu dat:", err)
	}

	f.Close()
}
```

## decrypt data using ReadMsg()
```go
package main

import (
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"os"

	erw "github.com/tomaspantlik/encreaderwriter"

	"github.com/youmark/pkcs8"
)

func main() {
	keyBytes, err := os.ReadFile("test.key")
	if err != nil {
		log.Fatal("error opening private key:", err)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "ENCRYPTED PRIVATE KEY" {
		log.Fatal("error opening private key: wrong type")
	}

	k, err := pkcs8.ParsePKCS8PrivateKey(keyBlock.Bytes, []byte("secretPassword"))
	if err != nil {
		log.Fatal("error opening private key:", err)
	}
	key, ok2 := k.(*rsa.PrivateKey)
	if !ok2 {
		log.Fatal("error opening private key: wrong type")
	}

	fr, err := os.Open("test.encrypted")
	if err != nil {
		log.Fatal("error opening encrypted file", err)
	}
	defer fr.Close()

	d, err := erw.OpenDecryptor(key, fr)
	if err != nil {
		log.Fatal("error opening encrypted file", err)
	}

	for {
		if data, err := d.ReadMsg(); err != nil {
			if errors.Is(err, io.EOF) {
				os.Exit(0)
			}
			log.Fatal("error decrypting data:", err)
		} else {
			log.Print("data:", string(data))
		}
	}
}
```

## decrypt data using Read()
```go
package main

import (
	"crypto/rsa"
	"encoding/pem"
	"io"
	"log"
	"os"

	erw "github.com/tomaspantlik/encreaderwriter"

	"github.com/youmark/pkcs8"
)

func main() {
	keyBytes, err := os.ReadFile("test.key")
	if err != nil {
		log.Fatal("error opening private key:", err)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || keyBlock.Type != "ENCRYPTED PRIVATE KEY" {
		log.Fatal("error opening private key: wrong type")
	}

	k, err := pkcs8.ParsePKCS8PrivateKey(keyBlock.Bytes, []byte("secretPassword"))
	if err != nil {
		log.Fatal("error opening private key:", err)
	}
	key, ok2 := k.(*rsa.PrivateKey)
	if !ok2 {
		log.Fatal("error opening private key: wrong type")
	}

	fr, err := os.Open("test.encrypted")
	if err != nil {
		log.Fatal("error opening encrypted file", err)
	}
	defer fr.Close()

	dr, err := erw.OpenDecryptReader(key, fr)
	if err != nil {
		log.Fatal("error opening encrypted file", err)
	}

	msgs, err := io.ReadAll(dr)
	if err != nil {
		log.Fatal("error decrypting data:", err)
	}
	log.Print("data:", string(msgs))
}
```
