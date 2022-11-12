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
	flag.StringVar(&cfg.AdminEmail, "k", cfg.AdminEmail, "secret key")
	flag.StringVar(&cfg.AdminEmail, "e", cfg.AdminEmail, "admin email")
	flag.StringVar(&cfg.AdminPassword, "p", cfg.AdminPassword, "admin password")
	flag.Parse()

	log.Fatal(server.Serve(&cfg))
}
