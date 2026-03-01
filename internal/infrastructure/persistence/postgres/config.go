package postgres

import "example.com/m/internal/infrastructure/env"

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func NewPostgresConfig() Config {
	return Config{
		Host:     env.GetString("DB_HOST", "localhost"),
		Port:     env.GetInt("DB_PORT", 5432),
		User:     env.GetString("DB_USER", "postgres"),
		Password: env.GetString("DB_PASSWORD", "password"),
		DBName:   env.GetString("DB_NAME", "app"),
		SSLMode:  env.GetString("DB_SSLMODE", "disable"),
	}
}
