package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
)

func main() {
	var key string = "12345678"
	var clearStr string
	fmt.Print("please input the clearStr: ")
	fmt.Scanf("%s\n", &clearStr)
	cipherStr, _ := Encrypt64(clearStr, key)
	fmt.Println("明文加密后:", cipherStr)
	desc, _ := Decrypt64(cipherStr, key)
	fmt.Println("密文解密后:", desc)
}

func Encrypt64(data, key string) (string, error) {
	out, err := Encrypt([]byte(data), []byte(key))
	return string(base64Encode(out)), err
}

func Decrypt64(data, key string) (string, error) {
	data1, err := base64Decode([]byte(data))
	if err != nil {
		return "", err
	}
	out, err2 := Decrypt(data1, []byte(key))
	return string(out), err2
}

func Encrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	data = PKCS5Padding(data, bs)
	blockMode := cipher.NewCBCEncrypter(block, key)
	out := make([]byte, len(data))
	blockMode.CryptBlocks(out, data)
	return out, nil
}
func Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	out := make([]byte, len(data))
	blockMode.CryptBlocks(out, data)
	out = PKCS5UnPadding(out)
	return out, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func base64Encode(src []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(src))
}

func base64Decode(src []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(src))
}
