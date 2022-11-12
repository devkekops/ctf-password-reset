package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"

	"github.com/devkekops/ctf-signature/internal/app/storage"
)

type BaseHandler struct {
	mux       *chi.Mux
	secretKey string
	fs        http.Handler
	userRepo  storage.PaymentRepository
}

func NewBaseHandler(userRepo storage.userRepository, secretKey string) *chi.Mux {
	cwd, _ := os.Getwd()
	root := filepath.Join(cwd, "/static")
	fs := http.FileServer(http.Dir(root))

	bh := &BaseHandler{
		mux:       chi.NewMux(),
		secretKey: secretKey,
		fs:        fs,
		userRepo:  userRepo,
	}

	bh.mux.Use(middleware.Logger)

	bh.mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	bh.mux.Handle("/*", fs)
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
func (bh *BaseHandler) signin() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

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
