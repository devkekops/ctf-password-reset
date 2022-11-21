package client

import (
	"bytes"
	"errors"
	"log"
	"net/smtp"
	"os"
	"path/filepath"
	"text/template"
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

type Mail struct {
	To         string
	Subject    string
	Text       string
	Link       string
	ButtonText string
}

type Client interface {
	SendMail(mail Mail) error
}

type SMTPClient struct {
	loginAuth smtp.Auth
	address   string
	from      string
	staticDir string
}

func NewClient(login string, password string, address string, from string) Client {
	cwd, _ := os.Getwd()
	staticDir := filepath.Join(cwd, "/static")

	return &SMTPClient{
		loginAuth: LoginAuth(login, password),
		address:   address,
		from:      from,
		staticDir: staticDir,
	}
}

func (c *SMTPClient) SendMail(mail Mail) error {
	headers := "Message-Id: 1\r\n" +
		"Date: " + time.Now().Format("2022-11-17") + "\r\n" +
		"From: " + c.from + "\r\n" +
		"To: " + mail.To + "\r\n"
	subject := "Subject: " + mail.Subject + "\r\n"
	mime := "MIME-Version: 1.0\n" + "Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n"

	tmpl := template.Must(template.ParseFiles(filepath.Join(c.staticDir, "mail.html")))
	buf := new(bytes.Buffer)
	tmpl.Execute(buf, mail)
	body := buf.String()

	msg := []byte(headers + subject + mime + body)

	err := smtp.SendMail(c.address, c.loginAuth, c.from, []string{mail.To}, msg)
	if err != nil {
		return err
	}
	log.Printf("Email to %s with subject %s sent successfully!\n", mail.To, mail.Subject)

	return nil
}
