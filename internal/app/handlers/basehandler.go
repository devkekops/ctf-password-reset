package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-passwd/validator"

	"github.com/devkekops/ctf-password-reset/internal/app/storage"
)

var MsgConfirmationIncorrect = "Something wrong with your confirmation..."
var ErrConfirmationIncorrect = errors.New("confirmation incorrect")
var ErrWrongDomain = errors.New("use your @sbermarket.ru email")
var ErrInvalidUserIDInContext = errors.New("invalid userID in context")

type BaseHandler struct {
	mux               *chi.Mux
	secretKey         string
	staticDir         string
	passwordValidator *validator.Validator
	userRepo          storage.UserRepository
}

type Msg struct {
	Msg      string
	HaveErr  bool
	ErrorMsg string
}

func createSession(userID string, secretKey string) string {
	userIDBytes := []byte(userID)

	key := sha256.Sum256([]byte(secretKey))
	h := hmac.New(sha256.New, key[:])
	h.Write(userIDBytes)
	dst := h.Sum(nil)

	sessionBytes := append(userIDBytes[:], dst[:]...)
	session := hex.EncodeToString(sessionBytes)

	return session
}

func getUserID(req *http.Request) (string, error) {
	userIDctx := req.Context().Value(userIDKey)
	userID, ok := userIDctx.(string)
	if !ok {
		return "", ErrInvalidUserIDInContext
	}
	return userID, nil
}

func NewBaseHandler(userRepo storage.UserRepository, secretKey string) *chi.Mux {
	cwd, _ := os.Getwd()
	staticDir := filepath.Join(cwd, "/static")

	passwordValidator := validator.New(validator.MinLength(8, nil), validator.Unique(nil), validator.CommonPassword(nil))

	bh := &BaseHandler{
		mux:               chi.NewMux(),
		secretKey:         secretKey,
		staticDir:         staticDir,
		passwordValidator: passwordValidator,
		userRepo:          userRepo,
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
	bh.mux.Get("/logout", bh.logout())
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
		userIDString, err := getUserID(req)
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "index.html")))
			tmpl.Execute(w, msg)
			return
		}

		userID, err := strconv.Atoi(userIDString)
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "index.html")))
			tmpl.Execute(w, msg)
			return
		}

		user, err := bh.userRepo.GetUserByID(userID)

		text := ""
		if !user.IsAdmin {
			text = "Welcome, " + user.Email + "! Your role: user."
		} else {
			text = "Welcome, " + user.Email + "! Your role: admin. Your know flag: sbmt_ctf_appsec_admin_always_knows_all_flags"
		}

		msg := Msg{text, false, ""}
		tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "index.html")))
		tmpl.Execute(w, msg)
	}
}

func (bh *BaseHandler) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     cookiePath,
			MaxAge:   0,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, req, "/login", 302)
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
		err := req.ParseForm()
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		formEmail, formPassword := req.PostForm["email"][0], req.PostForm["password"][0]

		_, err = mail.ParseAddress(formEmail)
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		domain := strings.Split(formEmail, "@")
		if domain[1] != "sbermarket.ru" {
			msg := Msg{"", true, ErrWrongDomain.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
			tmpl.Execute(w, msg)
			log.Println(ErrWrongDomain)
			return
		}

		err = bh.passwordValidator.Validate(formPassword)
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "signin.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		email, err := bh.userRepo.CreateUser(formEmail, formPassword)
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
			text = "Welcome, " + user.Email + "! Your role: admin. Your know flag: sbmt_ctf_appsec_admin_always_knows_all_flags"
		}

		session := createSession(strconv.Itoa(user.ID), bh.secretKey)
		cookie := &http.Cookie{
			Name:     cookieName,
			Value:    session,
			Path:     cookiePath,
			MaxAge:   cookieMaxAge,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)

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
		err := req.ParseForm()
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		formEmail := req.PostForm["email"][0]
		_, err = mail.ParseAddress(formEmail)
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		domain := strings.Split(formEmail, "@")
		if domain[1] != "sbermarket.ru" {
			msg := Msg{"", true, ErrWrongDomain.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(ErrWrongDomain)
			return
		}

		email, err := bh.userRepo.Reset(formEmail)
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

		err = req.ParseForm()
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		formPassword := req.PostForm["password"][0]
		err = bh.passwordValidator.Validate(formPassword)
		if err != nil {
			msg := Msg{"", true, err.Error()}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, "confirm_reset_pass.html")))
			tmpl.Execute(w, msg)
			log.Println(err)
			return
		}

		err = bh.userRepo.UpdatePassword(emailParams[1], formPassword, codeParams[1])
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
