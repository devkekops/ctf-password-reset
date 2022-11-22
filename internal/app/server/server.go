package server

import (
	"net/http"

	"github.com/devkekops/ctf-password-reset/internal/app/client"
	"github.com/devkekops/ctf-password-reset/internal/app/config"
	"github.com/devkekops/ctf-password-reset/internal/app/handlers"
	"github.com/devkekops/ctf-password-reset/internal/app/storage"
)

func Serve(cfg *config.Config) error {
	var client = client.NewClient(cfg.SMTPLogin, cfg.SMTPPassword, cfg.SMTPHost, cfg.FromEmail)

	var userRepo storage.UserRepository
	userRepo = storage.NewUserRepo(cfg.AdminEmail, cfg.AdminPassword, cfg.ServerAddress, client)

	var baseHandler = handlers.NewBaseHandler(userRepo, cfg.SecretKey, cfg.Flag)

	server := &http.Server{
		Addr:    cfg.ServerAddress,
		Handler: baseHandler,
	}

	return server.ListenAndServe()
}
