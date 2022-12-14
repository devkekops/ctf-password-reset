package main

import (
	"flag"
	"log"

	"github.com/caarlos0/env"
	"github.com/devkekops/ctf-password-reset/internal/app/config"
	"github.com/devkekops/ctf-password-reset/internal/app/server"
)

func main() {
	var cfg config.Config

	err := env.Parse(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	flag.StringVar(&cfg.ServerAddress, "a", cfg.ServerAddress, "server address")
	flag.StringVar(&cfg.SecretKey, "k", cfg.SecretKey, "secret key")
	flag.StringVar(&cfg.AdminEmail, "e", cfg.AdminEmail, "admin email")
	flag.StringVar(&cfg.AdminPassword, "c", cfg.AdminPassword, "admin password")
	flag.StringVar(&cfg.SMTPHost, "h", cfg.SMTPHost, "smtp host")
	flag.StringVar(&cfg.SMTPLogin, "l", cfg.SMTPLogin, "smtp login")
	flag.StringVar(&cfg.SMTPPassword, "p", cfg.SMTPPassword, "smtp password")
	flag.StringVar(&cfg.FromEmail, "s", cfg.FromEmail, "from email")
	flag.StringVar(&cfg.Flag, "f", cfg.Flag, "flag")
	flag.Parse()

	log.Fatal(server.Serve(&cfg))
}
