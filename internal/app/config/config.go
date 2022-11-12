package config

type Config struct {
	ServerAddress string `env:"SERVER_ADDRESS" envDefault:"0.0.0.0:8080"`
	SecretKey     string `env:"SECRET_KEY" envDefault:"lasndu4f7qwnflws83123ooqwd842939rd"`
	AdminEmail    string `env:"ADMIN_EMAIL" envDefault:"appsec@sbermarket.ru"`
	AdminPassword string `env:"ADMIN_PASSWORD" envDefault:"h7e8hfisahf74fhasdf4888990"`
}
