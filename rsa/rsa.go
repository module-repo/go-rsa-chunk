package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	BlockType_PublicKey     = "PUBLIC KEY"
	BlockType_RSAPublicKey  = "RSA PUBLIC KEY"
	BlockType_RSAPrivateKey = "RSA PRIVATE KEY"
)

const (
	RSAType_PKIX  = "PKIX"
	RSAType_PKCS1 = "PKCS1"
)

// GenerateRSA 生成RSA密钥对
func GenerateRSA(pubBlockType, priBlockType, rsaPubType string, size int) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, nil, err
	}
	priBlock := &pem.Block{
		Type:  priBlockType,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	priBuf := new(bytes.Buffer)
	pem.Encode(priBuf, priBlock) // pem.EncodeToMemory(block)

	var pubBytes []byte
	publicKey := &privateKey.PublicKey

	switch rsaPubType {
	case "PKIX":
		pubBytes, err = x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, nil, err
		}
	case "PKCS1":
		pubBytes = x509.MarshalPKCS1PublicKey(publicKey)
	default:
		return nil, nil, errors.New("unknown type, only PKIX or PKCS1")
	}

	pubBlock := &pem.Block{
		Type:  pubBlockType,
		Bytes: pubBytes,
	}
	pubBuf := new(bytes.Buffer)
	pem.Encode(pubBuf, pubBlock) // pem.EncodeToMemory(block)

	return priBuf.Bytes(), pubBuf.Bytes(), nil
}

// RSAEncryptBlock 公钥加密-分段
func RSAEncryptBlock(src, publicKeyByte []byte, rsaPubType string) (bytesEncrypt []byte, err error) {
	block, _ := pem.Decode(publicKeyByte)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	var pubKey interface{}

	switch rsaPubType {
	case "PKIX":
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	case "PKCS1":
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown type, only PKIX or PKCS1")
	}

	keySize, srcSize := pubKey.(*rsa.PublicKey).Size(), len(src)
	offSet, once := 0, keySize-11 //单次加密的长度需要减掉padding的长度，PKCS1为11
	buffer := bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + once
		if endIndex > srcSize {
			endIndex = srcSize
		}
		// 加密一部分
		bytesOnce, err2 := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), src[offSet:endIndex])
		if err2 != nil {
			return nil, err2
		}
		buffer.Write(bytesOnce)
		offSet = endIndex
	}
	bytesEncrypt = buffer.Bytes()
	return
}

// RSADecryptBlock 私钥解密-分段
func RSADecryptBlock(src, privateKeyBytes []byte, blockSize int) (bytesDecrypt []byte, err error) {
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, errors.New("private key error")
	}
	// 解析公钥
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	keySize, srcSize := privateKey.Size(), len(src)
	var offSet = 0
	var buffer = bytes.Buffer{}
	for offSet < srcSize {
		endIndex := offSet + keySize
		if endIndex > srcSize {
			endIndex = srcSize
		}
		if endIndex > blockSize {
			bytesOnce, err2 := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src[offSet:blockSize])
			if err2 != nil {
				return nil, err2
			}
			buffer.Write(bytesOnce)
		} else {
			bytesOnce, err2 := rsa.DecryptPKCS1v15(rand.Reader, privateKey, src[offSet:endIndex])
			if err2 != nil {
				return nil, err2
			}
			buffer.Write(bytesOnce)
		}
		offSet = endIndex
	}
	bytesDecrypt = buffer.Bytes()
	return
}
