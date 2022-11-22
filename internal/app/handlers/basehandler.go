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

const (
	signin             = "signin.html"
	confirm_signin     = "confirm_signin.html"
	login              = "login.html"
	reset_pass         = "reset_pass.html"
	confirm_reset_pass = "confirm_reset_pass.html"
	index              = "index.html"
	admin              = "admin.html"
	inform             = "inform.html"
)

type BaseHandler struct {
	mux               *chi.Mux
	secretKey         string
	flag              string
	staticDir         string
	passwordValidator *validator.Validator
	userRepo          storage.UserRepository
}

type Msg struct {
	Msg      string
	HaveErr  bool
	ErrorMsg string
}

type AdminMsg struct {
	Msg      string
	Users    []storage.User
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

func NewBaseHandler(userRepo storage.UserRepository, secretKey string, flag string) *chi.Mux {
	cwd, _ := os.Getwd()
	staticDir := filepath.Join(cwd, "/static")

	passwordValidator := validator.New(validator.MinLength(8, nil), validator.Unique(nil), validator.CommonPassword(nil))

	bh := &BaseHandler{
		mux:               chi.NewMux(),
		secretKey:         secretKey,
		flag:              flag,
		staticDir:         staticDir,
		passwordValidator: passwordValidator,
		userRepo:          userRepo,
	}

	bh.mux.Use(middleware.Logger)

	bh.mux.Get("/signin", bh.signin(signin))
	bh.mux.Post("/signin", bh.signinPost(signin))
	bh.mux.Get("/confirm_signin", bh.confirmSignin(confirm_signin))

	bh.mux.Get("/login", bh.login(login))
	bh.mux.Post("/login", bh.loginPost(login))

	bh.mux.Get("/reset_pass", bh.resetPass(reset_pass))
	bh.mux.Post("/reset_pass", bh.resetPassPost(reset_pass))

	bh.mux.Get("/confirm_reset_pass", bh.confirmResetPass(confirm_reset_pass))
	bh.mux.Post("/confirm_reset_pass", bh.confirmResetPassPost(confirm_reset_pass))

	bh.mux.Mount("/", bh.root())
	bh.mux.Get("/logout", bh.logout())
	return bh.mux
}

func (bh *BaseHandler) sendToTemplate(err error, text string, temp string, w http.ResponseWriter) {
	var msg Msg
	if err != nil {
		msg.HaveErr = true
		msg.ErrorMsg = err.Error()
	}
	msg.Msg = text

	tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, temp)))
	tmpl.Execute(w, msg)
}

func (bh *BaseHandler) root() http.Handler {
	r := chi.NewRouter()
	r.Use(authHandle(bh.secretKey))
	r.Get("/", bh.index(index))

	return r
}

func (bh *BaseHandler) index(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		userIDString, err := getUserID(req)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			return
		}

		userID, err := strconv.Atoi(userIDString)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			return
		}

		user, err := bh.userRepo.GetUserByID(userID)
		if err != nil {
			http.Redirect(w, req, "/login", 302)
		}

		if !user.IsAdmin {
			text := "Welcome, " + user.Email + "! Your role: user."
			bh.sendToTemplate(nil, text, index, w)
		} else {
			users := bh.userRepo.GetAllUsers()
			AdminMsg := AdminMsg{
				Msg:      "Welcome, " + user.Email + "! Your role: admin. Your know flag: " + bh.flag,
				Users:    users,
				HaveErr:  false,
				ErrorMsg: "",
			}
			tmpl := template.Must(template.ParseFiles(filepath.Join(bh.staticDir, admin)))
			tmpl.Execute(w, AdminMsg)
		}
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

func (bh *BaseHandler) signin(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		bh.sendToTemplate(nil, "", temp, w)
	}
}

func (bh *BaseHandler) signinPost(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		formEmail, formPassword := req.PostForm["email"][0], req.PostForm["password"][0]

		_, err = mail.ParseAddress(formEmail)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		domain := strings.Split(formEmail, "@")
		if domain[1] != "sbermarket.ru" {
			bh.sendToTemplate(ErrWrongDomain, "", temp, w)
			log.Println(ErrWrongDomain)
			return
		}

		err = bh.passwordValidator.Validate(formPassword)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		email, err := bh.userRepo.CreateUser(formEmail, formPassword)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		bh.sendToTemplate(nil, "We send confirmation to: "+email+". Please check email", inform, w)
	}
}

func (bh *BaseHandler) confirmSignin(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		confirmation := req.URL.Query().Get("confirmation")
		data, err := base64.StdEncoding.DecodeString(confirmation)
		if err != nil {
			bh.sendToTemplate(err, MsgConfirmationIncorrect, temp, w)
			log.Println(err)
			return
		}

		params := strings.Split(string(data), "&")
		if len(params) != 2 {
			bh.sendToTemplate(ErrConfirmationIncorrect, MsgConfirmationIncorrect, temp, w)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		emailParams := strings.Split(params[0], "=")
		codeParams := strings.Split(params[1], "=")
		if len(emailParams) != 2 || len(codeParams) != 2 {
			bh.sendToTemplate(ErrConfirmationIncorrect, MsgConfirmationIncorrect, temp, w)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		err = bh.userRepo.ConfirmUser(emailParams[1], codeParams[1])
		if err != nil {
			bh.sendToTemplate(err, MsgConfirmationIncorrect, temp, w)
			log.Println(err)
			return
		}

		bh.sendToTemplate(nil, "Email confirmed! Now please Login", inform, w)
	}
}

func (bh *BaseHandler) login(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		bh.sendToTemplate(nil, "", temp, w)
	}
}

func (bh *BaseHandler) loginPost(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		user, err := bh.userRepo.AuthUser(req.PostForm["email"][0], req.PostForm["password"][0])
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
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

		http.Redirect(w, req, "/", 302)
	}
}

func (bh *BaseHandler) resetPass(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		bh.sendToTemplate(nil, "", temp, w)
	}
}

func (bh *BaseHandler) resetPassPost(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		formEmail := req.PostForm["email"][0]
		_, err = mail.ParseAddress(formEmail)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		domain := strings.Split(formEmail, "@")
		if domain[1] != "sbermarket.ru" {
			bh.sendToTemplate(ErrWrongDomain, "", temp, w)
			log.Println(ErrWrongDomain)
			return
		}

		email, err := bh.userRepo.Reset(formEmail)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		bh.sendToTemplate(nil, "We send confirmation to: "+email+", please check email", inform, w)
	}
}

func (bh *BaseHandler) confirmResetPass(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		bh.sendToTemplate(nil, "", temp, w)
	}
}

func (bh *BaseHandler) confirmResetPassPost(temp string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		referer := req.Referer()
		url, err := url.ParseRequestURI(referer)
		if err != nil {
			bh.sendToTemplate(err, MsgConfirmationIncorrect, temp, w)
			log.Println(err)
			return
		}

		confirmation := url.Query().Get("confirmation")
		data, err := base64.StdEncoding.DecodeString(confirmation)
		if err != nil {
			bh.sendToTemplate(err, MsgConfirmationIncorrect, temp, w)
			log.Println(err)
			return
		}

		params := strings.Split(string(data), "&")
		if len(params) != 2 {
			bh.sendToTemplate(ErrConfirmationIncorrect, MsgConfirmationIncorrect, temp, w)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		emailParams := strings.Split(params[0], "=")
		codeParams := strings.Split(params[1], "=")
		if len(emailParams) != 2 || len(codeParams) != 2 {
			bh.sendToTemplate(ErrConfirmationIncorrect, MsgConfirmationIncorrect, temp, w)
			log.Println(ErrConfirmationIncorrect)
			return
		}

		err = req.ParseForm()
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		formPassword := req.PostForm["password"][0]
		err = bh.passwordValidator.Validate(formPassword)
		if err != nil {
			bh.sendToTemplate(err, "", temp, w)
			log.Println(err)
			return
		}

		err = bh.userRepo.UpdatePassword(emailParams[1], formPassword, codeParams[1])
		if err != nil {
			bh.sendToTemplate(err, MsgConfirmationIncorrect, temp, w)
			log.Println(err)
			return
		}

		bh.sendToTemplate(nil, "Password updated! Now Login please", inform, w)

	}
}
