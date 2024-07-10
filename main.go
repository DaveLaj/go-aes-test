package main

import (
	"crypto/aes"
	_ "crypto/rand"
	"fmt"
	"io"

	//"crypto/rsa"

	"encoding/base64"
	"encoding/json"
	_ "encoding/json"
	"log"

	"github.com/gin-gonic/gin"
)

type RequestToDecrypt struct {
	ToDecrypt string `json:"toDecrypt" binding:"required"`
}

func main() {
	err := CreateAESKeytoPemFile(byte16, "aes.pem")
	if err != nil {
		log.Println("Error creating AES key: ", err)
	}
	router := gin.Default()

	router.POST("/encryptAES", func(c *gin.Context) {
		var request map[string]interface{}

		jsonData, err := io.ReadAll(c.Request.Body)
		if err != nil {
			fmt.Println("error getting json data: %w", err)
			return
		}
		if err := json.Unmarshal(jsonData, &request); err != nil {
			fmt.Println("error unmarshalling json data: %w", err)
			return
		}
		marshalledJson, err := json.Marshal(request)
		if err != nil {
			fmt.Println("error marshalling json data: %w", err)
			return
		}
		key, err := ReadAESKeyFromPemFile("aes.pem")
		if err != nil {
			log.Println("Error reading AES key: ", err)
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			log.Println("Error creating AES cipher: ", err)
			return
		}

		ciphertext, err := AESEncryptWithGCM(marshalledJson, aesCipher)
		if err != nil {
			log.Println("Error encrypting: ", err)
		}
		fmt.Println(ciphertext)
		base64CipherText := base64.StdEncoding.EncodeToString(ciphertext)
		c.JSON(200, gin.H{"encrypted": base64CipherText})
	})

	router.POST("/decryptAES", func(c *gin.Context) {
		var request RequestToDecrypt
		err := c.BindJSON(&request)
		if err != nil {
			log.Println("Error parsing request: ", err)
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}
		key, err := ReadAESKeyFromPemFile("aes.pem")
		if err != nil {
			log.Println("Error reading AES key: ", err)
			c.JSON(500, gin.H{"error": "Internal server error"})
			return
		}
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			log.Println("Error creating AES cipher: ", err)
			return
		}

		decodedCipherText, err := base64.StdEncoding.DecodeString(request.ToDecrypt)
		fmt.Println(decodedCipherText)
		if err != nil {
			log.Println("Error decoding base64: ", err)
			c.JSON(400, gin.H{"error": "Invalid base64"})
			return
		}
		decryptedDataInBytes, err := AESDecryptWithGCM(decodedCipherText, aesCipher)
		if err != nil {
			log.Println("Error decrypting: ", err)
		}
		var decryptedBody map[string]interface{}
		if err := json.Unmarshal(decryptedDataInBytes, &decryptedBody); err != nil {
			c.JSON(500, gin.H{
				"message": err.Error(),
			})
		}
		c.Set("decryptedPayloadAsMap", decryptedBody)
		c.Set("decryptedPayloadAsBytes", decryptedDataInBytes)
		decryptedPayloadAsMap, exists := c.Get("decryptedPayloadAsMap")
		if !exists {
			fmt.Println("did not get decrypted payload")
			return
		}
		c.AbortWithStatusJSON(200, decryptedPayloadAsMap)
	})

	err = router.Run(":8080")
	if err != nil {
		log.Println("Error starting server: ", err)
	}
}
