package storage

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

var ErrUserAlreadyExists = errors.New("user already exists")
var ErrUserAlreadyConfirmed = errors.New("user already confirmed")
var ErrConfirmationCodeIncorrect = errors.New("confirmation code incorrect")
var ErrUserDoesNotExist = errors.New("user doesn't exists")
var ErrUserDoesNotConfirmed = errors.New("user doesn't confirmed")
var ErrPasswordIncorrect = errors.New("password incorrect")

type User struct {
	ID               int       `json:"id"`
	RegistrationDate time.Time `json:"registration_date"`
	Confirmed        bool      `json:"confirmed"`
	Email            string    `json:"email"`
	Password         string    `json:"password"`
	IsAdmin          bool      `json:"is_admin"`
	ConfirmationCode string
}

type UserRepository interface {
	//GetUserByID(int64) User
	CreateUser(string, string) (User, error)
	ConfirmUser(string, string) error
	AuthUser(string, string) (int, error)
	Reset(string) (User, error)
	UpdatePassword(string, string, string) error
}

type UserRepo struct {
	mutex          sync.RWMutex
	emailToUserMap map[string]User
}

func NewUserRepo(adminEmail string, adminPassword string) *UserRepo {
	emailToUserMap := make(map[string]User)

	adminUser := User{
		ID:               0,
		RegistrationDate: time.Now(),
		Confirmed:        true,
		Email:            adminEmail,
		Password:         adminPassword,
		IsAdmin:          true,
	}

	emailToUserMap[adminEmail] = adminUser

	return &UserRepo{
		emailToUserMap: emailToUserMap,
	}
}

const otpChars = "1234567890"

func generateOTP(length int) (string, error) {
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", err
	}

	otpCharsLength := len(otpChars)
	for i := 0; i < length; i++ {
		buffer[i] = otpChars[int(buffer[i])%otpCharsLength]
	}

	return string(buffer), nil
}

func (r *UserRepo) CreateUser(email string, password string) (User, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if user, ok := r.emailToUserMap[email]; ok {
		return user, ErrUserAlreadyExists
	}

	otp, err := generateOTP(6)
	if err == nil {
		return User{}, err
	}

	newUser := User{
		ID:               len(r.emailToUserMap),
		RegistrationDate: time.Now(),
		Confirmed:        false,
		Email:            email,
		Password:         password,
		IsAdmin:          false,
		ConfirmationCode: otp,
	}

	r.emailToUserMap[newUser.Email] = newUser

	return newUser, nil
}

func (r *UserRepo) ConfirmUser(email string, confirmationCode string) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if user, ok := r.emailToUserMap[email]; !ok {
		return ErrUserDoesNotExist
	} else {
		if user.Confirmed {
			return ErrUserAlreadyConfirmed
		}
		if user.ConfirmationCode != confirmationCode {
			return ErrConfirmationCodeIncorrect
		}
		user.ConfirmationCode = ""

		return nil
	}
}

func (r *UserRepo) AuthUser(email string, password string) (int, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if user, ok := r.emailToUserMap[email]; !ok {
		return 0, ErrUserDoesNotExist
	} else {
		if !user.Confirmed {
			return 0, ErrUserDoesNotConfirmed
		}

		if user.Password != password {
			return 0, ErrPasswordIncorrect
		}

		return user.ID, nil
	}
}

func (r *UserRepo) Reset(email string) (User, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if user, ok := r.emailToUserMap[email]; !ok {
		return User{}, ErrUserDoesNotExist
	} else {
		otp, err := generateOTP(6)
		if err == nil {
			return User{}, err
		}

		user.ConfirmationCode = otp
		return user, nil
	}
}

func (r *UserRepo) UpdatePassword(email string, password string, confirmationCode string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if user, ok := r.emailToUserMap[email]; !ok {
		return ErrUserDoesNotExist
	} else {
		if user.ConfirmationCode != confirmationCode {
			return ErrConfirmationCodeIncorrect
		}

		user.Password = password

		return nil
	}
}
