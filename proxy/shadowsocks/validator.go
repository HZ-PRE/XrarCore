package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"
	"time"

	"github.com/HZ-PRE/XrarCore/common/dice"
	"github.com/HZ-PRE/XrarCore/common/errors"
	"github.com/HZ-PRE/XrarCore/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users         sync.Map
	legacyUsers   sync.Map
	userSize      uint64
	onUsers       sync.Map
	onDayUsers    sync.Map
	onHourUsers   sync.Map
	behaviorSeed  uint64
	behaviorFused bool
}

var ErrNotFound = errors.New("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	email := strings.ToLower(u.Email)
	v.userSize = v.userSize + 1
	if _, ok := v.legacyUsers.Load(email); ok && !account.Cipher.IsAEAD() {
		v.legacyUsers.Store(email, u)
		return nil
	}
	v.users.Store(u.Email, u)
	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	v.onUsers.Delete(email)
	v.onHourUsers.Delete(email)
	v.onDayUsers.Delete(email)
	v.legacyUsers.Delete(email)
	v.users.Delete(email)
	v.userSize = v.userSize - 1
	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.Lock()
	defer v.Unlock()
	email = strings.ToLower(email)
	if value, ok := v.legacyUsers.Load(email); ok {
		return value.(*protocol.MemoryUser)
	}
	if value, ok := v.users.Load(email); ok {
		return value.(*protocol.MemoryUser)
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	var u = make([]*protocol.MemoryUser, 0, 100)
	v.users.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	v.legacyUsers.Range(func(key, value interface{}) bool {
		u = append(u, value.(*protocol.MemoryUser))
		return true
	})
	v.userSize = uint64(len(u))
	return u
}

// DetOnUsers 清除不在线用户
func (v *Validator) DetOnUsers() {
	v.Lock()
	defer v.Unlock()
	newDate := time.Now()
	v.onUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 10*time.Minute {
			v.onUsers.Delete(key)
		}
		return true
	})
	v.onHourUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 6*time.Hour {
			v.onHourUsers.Delete(key)
		}
		return true
	})
	v.onDayUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 24*time.Hour {
			v.onDayUsers.Delete(key)
		}
		return true
	})
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(v.userSize)
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	v.RLock()
	defer v.RUnlock()
	// AEAD payload decoding requires the payload to be over 32 bytes
	if len(bs) < 32 {
		v.legacyUsers.Range(func(key, value interface{}) bool {
			u = value.(*protocol.MemoryUser)
			ivLen = u.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.
			return false
		})
		return
	}
	newDate := time.Now()
	v.onUsers.Range(func(key, value interface{}) bool {
		if user, ok := v.users.Load(key); ok {
			u1 := user.(*protocol.MemoryUser)
			u, aead, ret, ivLen, err = checkAEADAndMatch(bs, u1, command)
			if u == nil {
				return true
			}
			v.onUsers.Store(u.Email, newDate)
			return false
		}
		return true

	})
	if u != nil {
		return
	}
	v.onHourUsers.Range(func(key, value interface{}) bool {
		if user, ok := v.users.Load(key); ok {
			u1 := user.(*protocol.MemoryUser)
			u, aead, ret, ivLen, err = checkAEADAndMatch(bs, u1, command)
			if u == nil {
				return true
			}
			v.onUsers.Store(u.Email, newDate)
			v.onHourUsers.Store(u.Email, newDate)
			return false
		}
		return true
	})
	if u != nil {
		return
	}
	v.onDayUsers.Range(func(key, value interface{}) bool {
		if user, ok := v.users.Load(key); ok {
			u1 := user.(*protocol.MemoryUser)
			u, aead, ret, ivLen, err = checkAEADAndMatch(bs, u1, command)
			if u == nil {
				return true
			}
			v.onUsers.Store(u.Email, newDate)
			v.onHourUsers.Store(u.Email, newDate)
			v.onDayUsers.Store(u.Email, newDate)
			return false
		}
		return true
	})
	if u != nil {
		return
	}
	v.users.Range(func(key, value interface{}) bool {
		user := value.(*protocol.MemoryUser)
		u, aead, ret, ivLen, err = checkAEADAndMatch(bs, user, command)
		if u == nil {
			return true
		}
		v.onUsers.Store(u.Email, newDate)
		v.onHourUsers.Store(u.Email, newDate)
		v.onDayUsers.Store(u.Email, newDate)
		return false
	})
	if u != nil {
		return
	}
	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}

func checkAEADAndMatch(bs []byte, user *protocol.MemoryUser, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	account := user.Account.(*MemoryAccount)
	aeadCipher := account.Cipher.(*AEADCipher)
	ivLen = aeadCipher.IVSize()
	iv := bs[:ivLen]
	subkey := make([]byte, 32)
	subkey = subkey[:aeadCipher.KeyBytes]
	hkdfSHA1(account.Key, iv, subkey)
	aead = aeadCipher.AEADAuthCreator(subkey)
	var matchErr error
	switch command {
	case protocol.RequestCommandTCP:
		data := make([]byte, 4+aead.NonceSize())
		ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
	case protocol.RequestCommandUDP:
		data := make([]byte, 8192)
		ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
	}

	if matchErr == nil {
		u = user
		err = account.CheckIV(iv)
		return
	}
	return nil, nil, nil, 0, matchErr
}
