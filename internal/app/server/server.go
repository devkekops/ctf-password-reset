package server

import (
	"net/http"

	"github.com/devkekops/ctf-password-reset/internal/app/config"
	"github.com/devkekops/ctf-password-reset/internal/app/handlers"
	"github.com/devkekops/ctf-password-reset/internal/app/storage"
)

func Serve(cfg *config.Config) error {
	var userRepo storage.UserRepository
	userRepo = storage.NewUserRepo(cfg.AdminEmail, cfg.AdminPassword)

	var baseHandler = handlers.NewBaseHandler(userRepo, cfg.SecretKey)

	server := &http.Server{
		Addr:    cfg.ServerAddress,
		Handler: baseHandler,
	}

	return server.ListenAndServe()
}
