package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestV1ProtocolEncryption(t *testing.T) {
	password := "1e369876-9034-4543-a70b-56b337e9f0a1"

	// 模拟 V1 协议 payload: ATYP(1) + UUID(16) + DST.ADDR + DST.PORT
	atyp := byte(0x01)
	uuid := "12345678-1234-abcd"
	dstAddr := []byte{127, 0, 0, 1}
	dstPort := []byte{0x01, 0xBB} // 443

	payload := []byte{atyp}
	payload = append(payload, []byte(uuid)...)
	payload = append(payload, dstAddr...)
	payload = append(payload, dstPort...)
	payload = append(payload, []byte("test data")...)

	fmt.Printf("原始 payload 长度: %d\n", len(payload))
	fmt.Printf("原始 payload hex: %x\n", payload)

	// 使用 aes-256-gcm 加密 (IVSize=32)
	key := passwordToCipherKeyLocal([]byte(password), 32)
	iv := make([]byte, 32)
	rand.Read(iv)

	fmt.Printf("IV: %x\n", iv)

	// HKDF 派生子密钥
	subkey := make([]byte, 32)
	hkdfSHA1Local(key, iv, subkey)

	// 创建 AEAD
	block, _ := aes.NewCipher(subkey)
	aead, _ := cipher.NewGCM(block)

	// SS AEAD 格式: [IV][加密长度块(18字节)][加密payload + tag]
	// 第一个 nonce (全0)
	nonce := make([]byte, aead.NonceSize())

	// 加密长度块 (2字节长度 + 16字节tag = 18字节)
	lenData := make([]byte, 2)
	lenData[0] = byte(len(payload) >> 8)
	lenData[1] = byte(len(payload))
	lenEncrypted := aead.Seal(nil, nonce, lenData, nil)
	fmt.Printf("长度块加密后 (18字节): %x\n", lenEncrypted)

	// 增加 nonce
	incrementNonceLocal(nonce)

	// 加密 payload
	payloadEncrypted := aead.Seal(nil, nonce, payload, nil)
	fmt.Printf("Payload 加密后长度: %d\n", len(payloadEncrypted))

	// 组合完整数据
	fullData := append(iv, lenEncrypted...)
	fullData = append(fullData, payloadEncrypted...)

	fmt.Printf("完整加密数据长度: %d\n", len(fullData))
	fmt.Printf("完整加密数据 hex: %x\n", fullData)

	// === 解密测试 ===
	fmt.Println("\n========== 解密测试 ==========")

	// 解密长度块
	decNonce := make([]byte, aead.NonceSize())
	decLenBlock := fullData[32:50] // 跳过 IV(32字节) 取 18 字节
	decLen, err := aead.Open(nil, decNonce, decLenBlock, nil)
	if err != nil {
		t.Fatalf("长度块解密失败: %v", err)
	}
	payloadLen := int(decLen[0])<<8 | int(decLen[1])
	fmt.Printf("解密后的长度: %d\n", payloadLen)

	// 增加 nonce 并解密 payload
	incrementNonceLocal(decNonce)
	decPayloadBlock := fullData[50:]
	decPayload, err := aead.Open(nil, decNonce, decPayloadBlock, nil)
	if err != nil {
		t.Fatalf("Payload 解密失败: %v", err)
	}
	fmt.Printf("解密后的 payload hex: %x\n", decPayload)
	fmt.Printf("解密后的 payload 字符串: %q\n", decPayload)

	// 解析 V1 格式
	if len(decPayload) >= 17 {
		fmt.Printf("ATYP: %02x\n", decPayload[0])
		extractedUUID := string(decPayload[1:17])
		fmt.Printf("提取的 UUID: %s\n", extractedUUID)
	}
}

// 辅助函数
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

func incrementNonceLocal(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}
