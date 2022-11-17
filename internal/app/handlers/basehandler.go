package handlers

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"

	"github.com/devkekops/ctf-password-reset/internal/app/storage"
)

type BaseHandler struct {
	mux       *chi.Mux
	secretKey string
	userRepo  storage.UserRepository
}

func NewBaseHandler(userRepo storage.UserRepository, secretKey string) *chi.Mux {
	bh := &BaseHandler{
		mux:       chi.NewMux(),
		secretKey: secretKey,
		userRepo:  userRepo,
	}

	bh.mux.Use(middleware.Logger)

	bh.mux.Handle("/*", bh.index())
	bh.mux.Handle("/admin", bh.admin())
	bh.mux.Route("/api", func(r chi.Router) {
		r.Post("/signin", bh.signin())
		r.Get("/confirm_signin", bh.confirmSignin())
		r.Post("/auth", bh.auth())
		r.Get("/account/{id}", bh.account())
		r.Post("/reset_pass", bh.resetPass())
		r.Get("/confirm_reset_pass", bh.confirmResetPass())
		r.Post("/update_pass", bh.updatePass())
	})

	return bh.mux
}

func (bh *BaseHandler) index() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		cwd, _ := os.Getwd()
		root := filepath.Join(cwd, "/static")

		http.ServeFile(w, req, root+"/index.html")
	}
}

func (bh *BaseHandler) admin() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		cwd, _ := os.Getwd()
		root := filepath.Join(cwd, "/static")

		http.ServeFile(w, req, root+"/admin.html")
	}
}

func (bh *BaseHandler) signin() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		_, err := bh.userRepo.CreateUser("dmitriy.tereshin@sbermarket.ru", "test")
		if err != nil {
			log.Println(err)
		}
	}
}

func (bh *BaseHandler) confirmSignin() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

	}
}

func (bh *BaseHandler) auth() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

	}
}

func (bh *BaseHandler) account() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

	}
}

func (bh *BaseHandler) resetPass() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		_, err := bh.userRepo.Reset("dmitriy.tereshin@sbermarket.ru")
		if err != nil {
			log.Println(err)
		}
	}
}

func (bh *BaseHandler) confirmResetPass() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

	}
}

func (bh *BaseHandler) updatePass() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

	}
}
