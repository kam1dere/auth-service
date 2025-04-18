package config

import (
	"time"
)

// Общая конфигурация сервиса, тут должны быть все переменные

type AppConfig struct {
	LogLevel   string
	GRPC       GRPC
	PostgreSQL PostgreSQL
	System     System
}

type GRPC struct {
	ListenAddress string `envconfig:"GRPC_LISTEN_ADDRESS" required:"true"`
}

type PostgreSQL struct {
	Host                string        `envconfig:"DB_HOST" required:"true"`
	Port                int           `envconfig:"DB_PORT" required:"true"`
	Name                string        `envconfig:"DB_NAME" required:"true"`
	User                string        `envconfig:"DB_USER" required:"true"`
	Password            string        `envconfig:"DB_PASSWORD" required:"true"`
	SSLMode             string        `envconfig:"DB_SSL_MODE" default:"disable"`
	PoolMaxConns        int           `envconfig:"DB_POOL_MAX_CONNS" default:"5"`
	PoolMaxConnLifetime time.Duration `envconfig:"DB_POOL_MAX_CONN_LIFETIME" default:"180s"`
	PoolMaxConnIdleTime time.Duration `envconfig:"DB_POOL_MAX_CONN_IDLE_TIME" default:"100s"`
}
type System struct {
	NumberPasswordAttempts int64         `envconfig:"NUMBER_PASSWORD_ATTEMPTS" default:"5"`
	LockPasswordEntry      time.Duration `envconfig:"LOCK_PASSWORD_ENTRY" default:"5m"`
	AccessTokenTimeout     time.Duration `envconfig:"ACCESS_TOKEN_TIMEOUT" default:"15m"`
	RefreshTokenTimeout    time.Duration `envconfig:"REFRESH_TOKEN_TIMEOUT" default:"15m"`
}
