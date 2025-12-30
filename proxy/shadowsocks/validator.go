package shadowsocks

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"runtime"
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

var (
	subkeyPool = sync.Pool{
		New: func() any {
			b := make([]byte, 32)
			return &b
		},
	}

	dataPool = sync.Pool{
		New: func() any {
			b := make([]byte, 8192) // 用于 UDP 的较大缓冲区
			return &b
		},
	}
)

var ErrNotFound = errors.New("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	email := strings.ToLower(u.Email)
	v.userSize = v.userSize + 1
	if !account.Cipher.IsAEAD() {
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
	var u = make([]*protocol.MemoryUser, 0, 2000)
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
	onHourUserSize := 0
	onDayUserSize := 0
	v.onDayUsers.Range(func(key, value interface{}) bool {
		m := value.(time.Time)
		duration := newDate.Sub(m)
		if duration > 24*time.Hour {
			v.onDayUsers.Delete(key)
		} else {
			onDayUserSize += 1
			if v1, ok := v.onHourUsers.Load(key); ok {
				m1 := v1.(time.Time)
				duration = newDate.Sub(m1)
				if duration > 6*time.Hour {
					v.onHourUsers.Delete(key)
				} else {
					onHourUserSize += 1
					if v2, ok2 := v.onUsers.Load(key); ok2 {
						m2 := v2.(time.Time)
						duration = newDate.Sub(m2)
						if duration > 11*time.Minute {
							v.onUsers.Delete(key)
						} else {
							onUserSize += 1
						}
					}
				}
			}
		}
		return true
	})
	v.onUserSize = onUserSize
	v.onHourUserSize = onHourUserSize
	v.onDayUserSize = onDayUserSize
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
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
	if v.onUserSize < 3000 {
		v.onUsers.Range(func(key, value interface{}) bool {
			if user, ok := v.users.Load(key); ok {
				u1 := user.(*protocol.MemoryUser)
				u, aead, ret, ivLen, err = checkAEADAndMatch(bs, u1, command)
				if u == nil {
					return true
				}
				v.touchUser(u.Email)
				return false
			}
			return true

		})
		if u != nil {
			return
		}
	} else {
		u, aead, ret, ivLen, err = processUsersInBatchesParallel(&v.users, &v.onUsers, bs, command, 3000)
		if u != nil {
			v.touchUser(u.Email)
			return
		}
	}
	if v.onHourUserSize < 5000 {
		v.onHourUsers.Range(func(key, value interface{}) bool {
			if user, ok := v.users.Load(key); ok {
				u1 := user.(*protocol.MemoryUser)
				u, aead, ret, ivLen, err = checkAEADAndMatch(bs, u1, command)
				if u == nil {
					return true
				}
				v.touchUser(u.Email)
				return false
			}
			return true

		})
		if u != nil {
			return
		}
	} else {
		u, aead, ret, ivLen, err = processUsersInBatchesParallel(&v.users, &v.onHourUsers, bs, command, 5000)
		if u != nil {
			v.touchUser(u.Email)
			return
		}
	}
	if v.onDayUserSize < 7000 {
		v.onDayUsers.Range(func(key, value interface{}) bool {
			if user, ok := v.users.Load(key); ok {
				u1 := user.(*protocol.MemoryUser)
				u, aead, ret, ivLen, err = checkAEADAndMatch(bs, u1, command)
				if u == nil {
					return true
				}
				v.touchUser(u.Email)
				return false
			}
			return true

		})
		if u != nil {
			return
		}
	} else {
		u, aead, ret, ivLen, err = processUsersInBatchesParallel(&v.users, &v.onDayUsers, bs, command, 7000)
		if u != nil {
			v.touchUser(u.Email)
			return
		}
	}

	u, aead, ret, ivLen, err = processUsersInBatchesParallel(nil, &v.users, bs, command, 14000)
	if u != nil {
		v.touchUser(u.Email)
		return
	}
	return nil, nil, nil, 0, ErrNotFound
}

// 使用并行处理的批量函数
func processUsersInBatchesParallel(userList *sync.Map, users *sync.Map, bs []byte, command protocol.RequestCommand, batchSize int) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	result := make(chan *batchResult, 1)

	batch := make([]*protocol.MemoryUser, 0, batchSize)
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	users.Range(func(key, value any) bool {
		var user *protocol.MemoryUser

		if userList != nil {
			if v, ok := userList.Load(key); ok {
				user = v.(*protocol.MemoryUser)
			} else {
				return true
			}
		} else {
			user = value.(*protocol.MemoryUser)
		}

		batch = append(batch, user)

		if len(batch) == batchSize {
			local := append([]*protocol.MemoryUser(nil), batch...)
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				userProcessBatch(ctx, &wg, local, bs, command, cancel, result)
			}()
			batch = batch[:0]
		}

		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	})

	if len(batch) > 0 {
		local := append([]*protocol.MemoryUser(nil), batch...)
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			userProcessBatch(ctx, &wg, local, bs, command, cancel, result)
		}()
	}

	go func() {
		wg.Wait()
		close(result)
	}()

	r, ok := <-result
	if ok {
		u = r.u
		aead = r.aead
		ret = r.ret
		ivLen = r.ivLen
		err = r.err
	} else {
		defer cancel()
	}
	return
}

func userProcessBatch(ctx context.Context, wg *sync.WaitGroup, batch []*protocol.MemoryUser, bs []byte, command protocol.RequestCommand, cancel context.CancelFunc, result chan<- *batchResult) {
	defer wg.Done()

	for _, user := range batch {
		select {
		case <-ctx.Done():
			return
		default:
			u, aead, ret, ivLen, err := checkAEADAndMatch(bs, user, command)
			if u != nil {
				select {
				case result <- &batchResult{
					u:     u,
					aead:  aead,
					ret:   ret,
					ivLen: ivLen,
					err:   err,
				}:
					cancel()
				default:
				}
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
func (v *Validator) touchUser(email string) {
	now := time.Now()
	v.onUsers.Store(email, now)
	v.onHourUsers.Store(email, now)
	v.onDayUsers.Store(email, now)
}

func checkAEADAndMatch(bs []byte, user *protocol.MemoryUser, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	account := user.Account.(*MemoryAccount)
	aeadCipher := account.Cipher.(*AEADCipher)
	ivLen = aeadCipher.IVSize()
	if ivLen < 8 {
		return
	}
	iv := bs[:ivLen]
	ptr := subkeyPool.Get().(*[]byte)
	defer subkeyPool.Put(ptr)
	subkey := *ptr
	subkey = subkey[:aeadCipher.KeyBytes]
	hkdfSHA1(account.Key, iv, subkey)
	aead = aeadCipher.AEADAuthCreator(subkey)
	var matchErr error
	var dataPtr *[]byte
	switch command {
	case protocol.RequestCommandTCP:
		dataPtr = dataPool.Get().(*[]byte)
		defer dataPool.Put(dataPtr)
		data := (*dataPtr)[:4+aead.NonceSize()]
		ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
	case protocol.RequestCommandUDP:
		dataPtr = dataPool.Get().(*[]byte)
		defer dataPool.Put(dataPtr)
		data := (*dataPtr)[:8192]
		ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
	}
	subkeyPool.Put(ptr)
	dataPool.Put(dataPtr)
	if matchErr == nil {
		u = user
		err = account.CheckIV(iv)
		return
	}
	return nil, nil, nil, 0, matchErr
}
