package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func main() {
	// the length of aes key should be 16/32/64/128...
	payloadSecret := "abcd1234abcd1234"
	originalJsonPayload := `{"name":"pablo","age":32}`
	fmt.Println("original payload is :", originalJsonPayload)

	// encrypt the payload
	encryptedJsonPayload, err := aesEncrypt(originalJsonPayload, payloadSecret)
	if err != nil {
		fmt.Println("encryption error:", err)
		return
	}
	fmt.Println("encrypt payload value is :", encryptedJsonPayload)

	// generate the new payload body
	newPayloadMap := map[string]string{
		"payload": encryptedJsonPayload,
	}
	newPayloadBytes, err := json.Marshal(newPayloadMap)
	if err != nil {
		fmt.Println("json marshal error:", err)
		return
	}
	newPayloadStr := string(newPayloadBytes)
	fmt.Println("new payload str is :", newPayloadStr)

	// generate the http header x-signature
	apiSecret := "ababababab"
	xSign := generateHMAC(encryptedJsonPayload, apiSecret)
	fmt.Println("x-sign is :", xSign)
}

// aesEncrypt implements AES/ECB/PKCS5Padding encryption
func aesEncrypt(plaintext, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// PKCS#7 padding (Go doesn't have PKCS#5 but PKCS#7 is a superset)
	blockSize := block.BlockSize()
	plaintextBytes := []byte(plaintext)
	padding := blockSize - len(plaintextBytes)%blockSize
	padtext := make([]byte, len(plaintextBytes)+padding)
	copy(padtext, plaintextBytes)
	for i := len(plaintextBytes); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	// ECB mode implementation (Go doesn't provide ECB mode directly)
	encrypted := make([]byte, len(padtext))
	for bs, be := 0, blockSize; bs < len(padtext); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encrypted[bs:be], padtext[bs:be])
	}

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// generateHMAC creates an HMAC SHA-256 signature
func generateHMAC(message, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	return bytesToHex(h.Sum(nil))
}

// bytesToHex converts bytes to hex string
func bytesToHex(bytes []byte) string {
	hexString := ""
	for _, b := range bytes {
		hex := fmt.Sprintf("%02x", b)
		hexString += hex
	}
	return hexString
}

// aesDecrypt 实现 AES/ECB/PKCS7Padding 解密
func aesDecrypt(encryptedText, key string) (string, error) {
	// 解码Base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	// 创建cipher
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// ECB模式解密
	blockSize := block.BlockSize()
	decrypted := make([]byte, len(encryptedBytes))

	// 按块解密
	for bs, be := 0, blockSize; bs < len(encryptedBytes); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted[bs:be], encryptedBytes[bs:be])
	}

	// 移除PKCS#7填充
	paddingLength := int(decrypted[len(decrypted)-1])
	if paddingLength > 0 && paddingLength <= blockSize {
		// 验证填充是否正确
		validPadding := true
		for i := len(decrypted) - paddingLength; i < len(decrypted); i++ {
			if decrypted[i] != byte(paddingLength) {
				validPadding = false
				break
			}
		}

		if validPadding {
			decrypted = decrypted[:len(decrypted)-paddingLength]
		}
	}

	return string(decrypted), nil
}

