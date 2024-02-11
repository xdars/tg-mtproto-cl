package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func AesDecrypt(key, iv, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	if len(data) < aes.BlockSize {
		fmt.Println("block size short")
		return nil
	}
	iv = data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	fmt.Println("Decrypted data length:", len(data))
	return data

}
func genTmpKeys(nonceSecond, nonceServer []byte) (key, iv []byte) {
	fmt.Println("Generating tmp keys")
	fmt.Println("newNonce", hex.EncodeToString(nonceSecond))
	fmt.Println("nonceServer", hex.EncodeToString(nonceServer))

	b0 := make([]byte, len(nonceSecond)+len(nonceServer))
	b1 := make([]byte, len(nonceSecond)+len(nonceServer))

	copy(b0[:len(nonceSecond)], nonceSecond)
	copy(b0[len(nonceSecond):], nonceServer)

	copy(b1[:len(nonceServer)], nonceServer)
	copy(b1[len(nonceServer):], nonceSecond)

	b0Hash := sha1.New()
	b1Hash := sha1.New()

	b0Hash.Write(b0)
	b1Hash.Write(b1)

	tmpAESKey := make([]byte, 32)
	copy(tmpAESKey[:len(b0Hash.Sum(nil))], b0Hash.Sum(nil))
	copy(tmpAESKey[len(b0Hash.Sum(nil)):], b1Hash.Sum(nil)[:12])

	fmt.Println("tmp_aes_key:", hex.EncodeToString(tmpAESKey))

	b2 := make([]byte, len(nonceSecond)*2)
	copy(b2[:len(nonceSecond)], nonceSecond)
	copy(b2[len(nonceSecond):], nonceSecond)

	b2Hash := sha1.New()
	b2Hash.Write(b2)

	tmpAESIV := make([]byte, 32)
	copy(tmpAESIV[0:], b1Hash.Sum(nil)[12:12+8])
	copy(tmpAESIV[8:], b2Hash.Sum(nil))
	copy(tmpAESIV[28:], nonceSecond[0:4])

	fmt.Println("tmp_aes_iv:", hex.EncodeToString(tmpAESIV), len(tmpAESIV))
	return tmpAESKey, tmpAESIV
}
