package config

type Config struct {
	ServerAddress string `env:"SERVER_ADDRESS" envDefault:"0.0.0.0:80"`
	SecretKey     string `env:"SECRET_KEY"`
	AdminEmail    string `env:"ADMIN_EMAIL"`
	AdminPassword string `env:"ADMIN_PASSWORD"`
	SMTPHost      string `env:"SMTP_HOST"`
	SMTPLogin     string `env:"SMTP_LOGIN"`
	SMTPPassword  string `env:"SMTP_PASSWORD"`
	FromEmail     string `env:"FROM_EMAIL"`
}
