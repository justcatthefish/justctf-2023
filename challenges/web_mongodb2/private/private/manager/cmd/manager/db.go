package main

import (
	"errors"
	"net/url"
	"sync"
	"time"
)

type db struct {
	muUser    sync.RWMutex
	muSandbox sync.RWMutex

	dbUser    map[string]UserData
	dbSandbox map[string]UserData

	dbPorts map[int]bool
}

func NewDB() (*db, error) {
	return &db{
		dbUser:    make(map[string]UserData),
		dbSandbox: make(map[string]UserData),
		dbPorts:   make(map[int]bool),
	}, nil
}

func (d *db) Init() error {
	return nil
}

type UserData struct {
	TargetURL   *url.URL
	UserIP      string
	ExpireAt    time.Time
	Token       string
	OneTimeHash string
	Cpu         *int
}

func (u UserData) NeedRefreshOneTimeHash() bool {
	return time.Now().After(u.ExpireAt)
}

var ErrUserNotExists = errors.New("user not exists")

func (d *db) UpdateUser(user UserData) error {
	d.muUser.Lock()
	defer d.muUser.Unlock()
	d.dbUser[user.UserIP] = user
	return nil
}

func (d *db) UpdateSandbox(user UserData) error {
	d.muSandbox.Lock()
	defer d.muSandbox.Unlock()
	d.dbSandbox[user.Token] = user
	return nil
}

func (d *db) BumpSandbox(user UserData) error {
	d.muSandbox.Lock()
	defer d.muSandbox.Unlock()
	user.ExpireAt = time.Now().Add(Config.SandboxDuration)
	d.dbSandbox[user.Token] = user
	return nil
}

func (d *db) DeleteSandbox(userToken string) error {
	d.muUser.Lock()
	defer d.muUser.Unlock()
	d.muSandbox.Lock()
	defer d.muSandbox.Unlock()

	userData, err := d.unsafeGetSandboxByToken(userToken)
	if err == nil && userData.Cpu != nil {
		d.unsafeFreeCpu(*userData.Cpu)
		delete(d.dbUser, userData.UserIP)
	}
	delete(d.dbSandbox, userToken)
	return nil
}

func (d *db) unsafeGetSandboxByToken(token string) (UserData, error) {
	if out, exists := d.dbSandbox[token]; exists {
		return out, nil
	}
	return UserData{}, ErrUserNotExists
}

func (d *db) GetSandboxByToken(token string) (UserData, error) {
	d.muSandbox.RLock()
	defer d.muSandbox.RUnlock()
	return d.unsafeGetSandboxByToken(token)
}

func (d *db) GetUserByIP(userIP string) (UserData, error) {
	d.muUser.RLock()
	defer d.muUser.RUnlock()
	if out, exists := d.dbUser[userIP]; exists {
		return out, nil
	}
	return UserData{}, ErrUserNotExists
}

var ErrNoFreeCpu = errors.New("no free cpu")

func (d *db) GetFreeCpu() (int, error) {
	d.muUser.Lock()
	defer d.muUser.Unlock()

	var freeCpu int
	for i := 1; i < Config.MaxCores; i++ {
		if _, exists := d.dbPorts[i]; exists {
			continue
		}
		freeCpu = i
		break
	}
	if freeCpu == 0 {
		return 0, ErrNoFreeCpu
	}
	d.dbPorts[freeCpu] = true
	return freeCpu, nil
}

func (d *db) unsafeFreeCpu(cpuUid int) error {
	delete(d.dbPorts, cpuUid)
	return nil
}
