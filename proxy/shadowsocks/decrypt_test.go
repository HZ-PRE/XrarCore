package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// func isUUID(s string) bool {
// 	// UUID的正则表达式匹配模式，包括带短横线和不带短横线的版本
// 	uuidPattern := `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
// 	uuidNoHyphenPattern := `^[0-9a-fA-F]{32}$`

// 	// 编译正则表达式
// 	re := regexp.MustCompile(uuidPattern)
// 	reNoHyphen := regexp.MustCompile(uuidNoHyphenPattern)

//		// 检测字符串是否匹配正则表达式
//		return re.MatchString(s) || reNoHyphen.MatchString(s)
//	}
func TestDecryptData(t *testing.T) {
	// 新的原始数据
	hexData := "b931653336393837362d393033342d343534332d613730622d3536623333376539663061657c73245f2a89d93ad2bee8a54d"
	bs, _ := hex.DecodeString(hexData)
	fmt.Printf("原始数据长度: %d 字节\n", len(bs))
	fmt.Printf("原始数据 hex: %x\n", bs)

	// 尝试作为 ASCII 解码
	fmt.Printf("\n作为 ASCII: %s\n", string(bs))
	uuidStr := string(bs[1:37])
	fmt.Printf("从位置1开始的 ASCII: %s\n", uuidStr)
	if isUUID(uuidStr) {
		fmt.Printf("提取的字符串是一个有效的 UUID: %s\n", uuidStr)
	} else {
		fmt.Printf("提取的字符串不是一个有效的 UUID: %s\n", uuidStr)
	}
}

// 本地辅助函数
func passwordToCipherKeyLocal(password []byte, keySize int32) []byte {
	key := make([]byte, 0, keySize)
	md5Sum := md5.Sum(password)
	key = append(key, md5Sum[:]...)
	for int32(len(key)) < keySize {
		md5Hash := md5.New()
		md5Hash.Write(md5Sum[:])
		md5Hash.Write(password)
		md5Hash.Sum(md5Sum[:0])
		key = append(key, md5Sum[:]...)
	}
	return key
}

func hkdfSHA1Local(secret, salt, outKey []byte) {
	r := hkdf.New(sha1.New, secret, salt, []byte("ss-subkey"))
	io.ReadFull(r, outKey)
}

func createAesGcmLocal(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm
}

func createChaCha20Poly1305Local(key []byte) cipher.AEAD {
	c, _ := chacha20poly1305.New(key)
	return c
}

func createXChaCha20Poly1305Local(key []byte) cipher.AEAD {
	c, _ := chacha20poly1305.NewX(key)
	return c
}
