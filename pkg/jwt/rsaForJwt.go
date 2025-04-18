package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func ReadPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ReadPublicKey() (*rsa.PublicKey, error) {
	publicKeyBytes, err := ioutil.ReadFile("public.pem")
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicKeyBytes)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Failed to parse public key")
	}

	return publicKey, nil
}
