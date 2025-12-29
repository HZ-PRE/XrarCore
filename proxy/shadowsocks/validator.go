package shadowsocks

import (
	"context"
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
	users          sync.Map
	userSize       int
	legacyUsers    sync.Map
	onUsers        sync.Map
	onUserSize     int
	onDayUsers     sync.Map
	onDayUserSize  int
	onHourUsers    sync.Map
	onHourUserSize int
	behaviorSeed   uint64
	behaviorFused  bool
}
type batchResult struct {
	u     *protocol.MemoryUser
	aead  cipher.AEAD
	ret   []byte
	ivLen int32
	err   error
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
	if _, ok := v.users.Load(email); !ok {
		return nil
	}
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
	v.userSize = len(u)
	return u
}

// DetOnUsers 清除不在线用户
func (v *Validator) DetOnUsers() {
	v.Lock()
	defer v.Unlock()
	newDate := time.Now()
	onUserSize := 0
	v.onUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 11*time.Minute {
			v.onUsers.Delete(key)
		} else {
			onUserSize += 1
		}
		return true
	})
	onHourUserSize := 0
	v.onHourUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 6*time.Hour {
			v.onHourUsers.Delete(key)
		} else {
			onHourUserSize += 1
		}
		return true
	})
	onDayUserSize := 0
	v.onDayUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 24*time.Hour {
			v.onDayUsers.Delete(key)
		} else {
			onDayUserSize += 1
		}
		return true
	})
	v.onUserSize = onUserSize
	v.onHourUserSize = onHourUserSize
	v.onDayUserSize = onDayUserSize
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
	if v.onUserSize < 2000 {
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
	} else {
		u, aead, ret, ivLen, err = processUsersInBatchesParallel(&v.users, &v.onUsers, bs, command, 2000)
		if u != nil {
			v.onUsers.Store(u.Email, newDate)
			return
		}
	}
	if v.onHourUserSize < 4000 {
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
	} else {
		u, aead, ret, ivLen, err = processUsersInBatchesParallel(&v.users, &v.onHourUsers, bs, command, 4000)
		if u != nil {
			v.onUsers.Store(u.Email, newDate)
			v.onHourUsers.Store(u.Email, newDate)
			return
		}
	}
	if v.onDayUserSize < 5000 {
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
	} else {
		u, aead, ret, ivLen, err = processUsersInBatchesParallel(&v.users, &v.onDayUsers, bs, command, 5000)
		if u != nil {
			v.onUsers.Store(u.Email, newDate)
			v.onHourUsers.Store(u.Email, newDate)
			v.onDayUsers.Store(u.Email, newDate)
			return
		}
	}

	u, aead, ret, ivLen, err = processUsersInBatchesParallel(nil, &v.users, bs, command, 5000)
	if u != nil {
		v.onUsers.Store(u.Email, newDate)
		v.onHourUsers.Store(u.Email, newDate)
		v.onDayUsers.Store(u.Email, newDate)
		return
	}
	return nil, nil, nil, 0, ErrNotFound
}

// 使用并行处理的批量函数
func processUsersInBatchesParallel(userList *sync.Map, users *sync.Map, bs []byte, command protocol.RequestCommand, batchSize uint64) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	userBatch := make([]*protocol.MemoryUser, 0, int(batchSize))
	var wg sync.WaitGroup

	ret1 := make(chan *batchResult, 1)
	// 创建一个可取消的上下文
	ctx, cancel := context.WithCancel(context.Background())

	users.Range(func(key, value interface{}) bool {
		var user *protocol.MemoryUser
		if userList != nil {
			if u1, ok := userList.Load(key); ok {
				user = u1.(*protocol.MemoryUser)
			}
		} else {
			user = value.(*protocol.MemoryUser)
		}
		userBatch = append(userBatch, user)

		// 当批次达到指定大小时，启动一个 goroutine 来处理该批次
		if len(userBatch) >= int(batchSize) {
			wg.Add(1)
			go userProcessBatch(userBatch, &wg, bs, command, cancel, ret1)
			userBatch = userBatch[:0] // 清空当前批次
		}

		// 如果 ctx 已取消，退出 Range 遍历
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	})

	// 如果最后有剩余的用户（未满批次），并行处理
	if len(userBatch) > 0 {
		wg.Add(1)
		go userProcessBatch(userBatch, &wg, bs, command, cancel, ret1)
	}

	// 等待所有 goroutine 完成
	wg.Wait()
	r1 := <-ret1
	if r1.u != nil {
		u = r1.u
		aead = r1.aead
		ret = r1.ret
		ivLen = r1.ivLen
		err = r1.err
	}
	return
}

// 处理批次的函数
func userProcessBatch(batch []*protocol.MemoryUser, wg *sync.WaitGroup, bs []byte, command protocol.RequestCommand, cancel context.CancelFunc, ret chan<- *batchResult) {
	defer wg.Done()
	for _, user := range batch {
		// 如果上下文已经被取消，退出循环
		select {
		case <-context.Background().Done():
			return // 上下文已取消，退出
		default:
			u, aead, retData, ivLen, err := checkAEADAndMatch(bs, user, command)
			if u != nil {
				ret <- &batchResult{
					u:     u,
					aead:  aead,
					ret:   retData,
					ivLen: ivLen,
					err:   err,
				}
				cancel() // 取消所有并行任务
				return
			}
		}
	}
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
