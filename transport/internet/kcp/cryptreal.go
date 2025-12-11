package kcp

import (
	"crypto/cipher"
	"crypto/sha256"

	"github.com/HZ-PRE/XrarCore/common/crypto"
)

func NewAEADAESGCMBasedOnSeed(seed string) cipher.AEAD {
	hashedSeed := sha256.Sum256([]byte(seed))
	return crypto.NewAesGcm(hashedSeed[:16])
}
