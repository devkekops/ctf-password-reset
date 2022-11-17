package client

import (
	"errors"
	"fmt"
	"net/smtp"
	"time"
)

type loginAuth struct {
	username, password string
}

func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("Unkown fromServer")
		}
	}
	return nil, nil
}

type Client interface {
	SendMail(to string, subj string, msg string) error
}

type SMTPClient struct {
	loginAuth smtp.Auth
	address   string
	from      string
}

func NewClient(login string, password string, address string, from string) Client {
	return &SMTPClient{
		loginAuth: LoginAuth(login, password),
		address:   address,
		from:      from,
	}
}

func (c *SMTPClient) SendMail(to string, subj string, msg string) error {

	mail := []byte("Message-Id: 1\r\n" +
		"Date: " + time.Now().Format("2022-11-17") + "\r\n" +
		"From: " + c.from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subj + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"\r\n" +
		msg + "\r\n")

	err := smtp.SendMail(c.address, c.loginAuth, c.from, []string{to}, mail)
	if err != nil {
		return err
	}
	fmt.Println("Email Sent Successfully!")

	return nil
}
