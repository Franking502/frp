package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// key 长度必须是 16 / 24 / 32 字节（AES-128/192/256）
var key = []byte("0123456789abcdef0123456789abcdef") // 32字节 = AES-256

// Encrypt 字符串加密 → 可打印字符串
func Encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)

	// Base64 编码，保证可打印
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "用法: %s <文件路径>\n", os.Args[0])
		os.Exit(1)
	}

	filePath := os.Args[1]

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取文件失败: %v\n", err)
		os.Exit(1)
	}

	encrypted, err := Encrypt(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "加密失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(encrypted)
}
