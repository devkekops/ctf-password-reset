package storage

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/devkekops/ctf-password-reset/internal/app/client"
)

var ErrUserAlreadyExists = errors.New("user already exists")
var ErrUserAlreadyConfirmed = errors.New("user already confirmed")
var ErrConfirmationCodeIncorrect = errors.New("confirmation code incorrect")
var ErrUserDoesNotExist = errors.New("user doesn't exists")
var ErrUserDoesNotConfirmed = errors.New("user doesn't confirmed")
var ErrPasswordIncorrect = errors.New("password incorrect")
var ErrCanNotSendEmail = errors.New("can not send email")

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
	CreateUser(email string, password string) (string, error)
	ConfirmUser(email string, confirmationCode string) error
	AuthUser(email string, password string) (User, error)
	Reset(email string) (string, error)
	UpdatePassword(email string, password string, confirmationCode string) error
}

type UserRepo struct {
	mutex          sync.RWMutex
	serverAddress  string
	client         client.Client
	emailToUserMap map[string]User
}

func NewUserRepo(adminEmail string, adminPassword string, serverAddress string, client client.Client) *UserRepo {
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
		mutex:          sync.RWMutex{},
		serverAddress:  serverAddress,
		client:         client,
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

func generateLink(serverAddress string, path string, email string, otp string) string {
	confirmation := base64.StdEncoding.EncodeToString([]byte("email=" + email + "&code=" + otp))

	link := "http://" + serverAddress + "/" + path + "?confirmation=" + confirmation

	return link
}

func (r *UserRepo) CreateUser(email string, password string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if user, ok := r.emailToUserMap[email]; ok {
		return user.Email, ErrUserAlreadyExists
	}

	otp, err := generateOTP(4)
	if err != nil {
		return "", err
	}

	err = r.client.SendMail(email, "Email Confirmation", "This is your email confirmation link:\n"+generateLink(r.serverAddress, "confirm_signin", email, otp))
	if err != nil {
		return "", ErrCanNotSendEmail
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

	return newUser.Email, nil
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
		user.Confirmed = true

		r.emailToUserMap[user.Email] = user

		return nil
	}
}

func (r *UserRepo) AuthUser(email string, password string) (User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if user, ok := r.emailToUserMap[email]; !ok {
		return User{}, ErrUserDoesNotExist
	} else {
		if !user.Confirmed {
			return User{}, ErrUserDoesNotConfirmed
		}

		if user.Password != password {
			return User{}, ErrPasswordIncorrect
		}

		return user, nil
	}
}

func (r *UserRepo) Reset(email string) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if user, ok := r.emailToUserMap[email]; !ok {
		return "", ErrUserDoesNotExist
	} else {
		otp, err := generateOTP(4)
		if err != nil {
			return "", err
		}

		err = r.client.SendMail(email, "Reset Password", "This is your reset password link:\n"+generateLink(r.serverAddress, "confirm_reset_pass", email, otp))
		if err != nil {
			return "", ErrCanNotSendEmail
		}

		user.ConfirmationCode = otp
		r.emailToUserMap[user.Email] = user

		return user.Email, nil
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
		r.emailToUserMap[user.Email] = user

		return nil
	}
}
