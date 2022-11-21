package handlers

import (
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"

	"github.com/devkekops/ctf-password-reset/internal/app/storage"
)

var ErrConfirmationIncorrect = errors.New("confirmation incorrect")
var MsgConfirmationIncorrect = "Something wrong with your confirmation..."

type BaseHandler struct {
	mux       *chi.Mux
	secretKey string
	staticDir string
	userRepo  storage.UserRepository
}

type Msg struct {
	Msg      string
	HaveErr  bool
	ErrorMsg string
}

func NewBaseHandler(userRepo storage.UserRepository, secretKey string) *chi.Mux {
	cwd, _ := os.Getwd()
	staticDir := filepath.Join(cwd, "/static")

	bh := &BaseHandler{
		mux:       chi.NewMux(),
		secretKey: secretKey,
		staticDir: staticDir,
		userRepo:  userRepo,
	}

	bh.mux.Use(middleware.Logger)

	bh.mux.Get("/signin", bh.signin())
	bh.mux.Post("/signin", bh.signinPost())
	bh.mux.Get("/confirm_signin", bh.confirmSignin())

	bh.mux.Get("/login", bh.login())
	bh.mux.Post("/login", bh.loginPost())

	bh.mux.Get("/reset_pass", bh.resetPass())
	bh.mux.Post("/reset_pass", bh.resetPassPost())

	bh.mux.Get("/confirm_reset_pass", bh.confirmResetPass())
	bh.mux.Post("/confirm_reset_pass", bh.confirmResetPassPost())

	bh.mux.Mount("/", bh.root())
	return bh.mux
}

func (bh *BaseHandler) root() http.Handler {
	r := chi.NewRouter()
	r.Use(authHandle(bh.secretKey))
	r.Get("/", bh.index())

	return r
}

func (bh *BaseHandler) index() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		msg := Msg{"", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "index.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) signin() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		msg := Msg{"", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) signinPost() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		email, err := bh.userRepo.CreateUser(req.PostForm["email"][0], req.PostForm["password"][0])
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		msg := Msg{"We send confirmation to: " + email + ", please check email", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "inform.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) confirmSignin() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		confirmation := req.URL.Query().Get("confirmation")
		data, err := base64.StdEncoding.DecodeString(confirmation)
		if err != nil {
			msg := Msg{MsgConfirmationIncorrect, true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		params := strings.Split(string(data), "&")
		if len(params) != 2 {
			msg := Msg{MsgConfirmationIncorrect, true, ErrConfirmationIncorrect.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_signin.html")))
			tmpl.Execute(w, msg)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		emailParams := strings.Split(params[0], "=")
		codeParams := strings.Split(params[1], "=")
		if len(emailParams) != 2 || len(codeParams) != 2 {
			msg := Msg{MsgConfirmationIncorrect, true, ErrConfirmationIncorrect.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_signin.html")))
			tmpl.Execute(w, msg)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		err = bh.userRepo.ConfirmUser(emailParams[1], codeParams[1])
		if err != nil {
			msg := Msg{MsgConfirmationIncorrect, true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		msg := Msg{"Email confirmed! Now Login please", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "inform.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) login() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		msg := Msg{"", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "login.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) loginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "login.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		user, err := bh.userRepo.AuthUser(req.PostForm["email"][0], req.PostForm["password"][0])
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "login.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		text := ""
		if !user.IsAdmin {
			text = "Welcome, " + user.Email + "! Your role: user."
		} else {
			text = "Welcome, " + user.Email + "! Your role: admin. Your know flag: admin_knows_all_flags"
		}

		msg := Msg{text, false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "index.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) resetPass() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		msg := Msg{"", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "reset_pass.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) resetPassPost() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		email, err := bh.userRepo.Reset(req.PostForm["email"][0])
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		msg := Msg{"We send confirmation to: " + email + ", please check email", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "inform.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) confirmResetPass() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		msg := Msg{"", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) confirmResetPassPost() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		referer := req.Referer()
		url, err := url.ParseRequestURI(referer)
		if err != nil {
			msg := Msg{MsgConfirmationIncorrect, true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		confirmation := url.Query().Get("confirmation")
		data, err := base64.StdEncoding.DecodeString(confirmation)
		if err != nil {
			msg := Msg{MsgConfirmationIncorrect, true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		params := strings.Split(string(data), "&")
		if len(params) != 2 {
			msg := Msg{MsgConfirmationIncorrect, true, ErrConfirmationIncorrect.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		emailParams := strings.Split(params[0], "=")
		codeParams := strings.Split(params[1], "=")
		if len(emailParams) != 2 || len(codeParams) != 2 {
			msg := Msg{MsgConfirmationIncorrect, true, ErrConfirmationIncorrect.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		if err := req.ParseForm(); err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		err = bh.userRepo.UpdatePassword(emailParams[1], req.PostForm["password"][0], codeParams[1])
		if err != nil {
			msg := Msg{MsgConfirmationIncorrect, true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		msg := Msg{"Password updated! Now Login please", false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "inform.html")))
		tmpl.Execute(w, msg)

	}
}
