package repo

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"

	"auth-service/internal/config"
)

type Repository interface {
	// Пользовательские методы.
	CreateUser(ctx context.Context, user *User) (int64, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetPassword(ctx context.Context, userID int64) (string, error)
	UpdatePassword(ctx context.Context, params UpdatePasswordParams) error

	// Методы работы с токенами.
	NewRefreshToken(ctx context.Context, params NewRefreshTokenParams) (int64, error)
	DeleteRefreshToken(ctx context.Context, params DeleteRefreshTokenParams) error
	GetRefreshToken(ctx context.Context, params GetRefreshTokenParams) ([]string, error)
	UpdateRefreshToken(ctx context.Context, params UpdateRefreshTokenParams) error
}

const (
	createUserQuery = `
		INSERT INTO users (username, hashed_password, email, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id;
	`

	getUserByUsernameQuery = `
		SELECT id, username, hashed_password, email, created_at, updated_at
		FROM users
		WHERE username = $1;
	`

	getPasswordQuery = `
		SELECT hashed_password
		FROM users
		WHERE id = $1;
	`

	updatePasswordQuery = `
		UPDATE users
		SET hashed_password = $1, updated_at = NOW()
		WHERE id = $2;
	`

	insertRefreshTokenQuery = `
		INSERT INTO auth_tokens (user_id, refresh_token, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		RETURNING id;
	`

	deleteRefreshTokenQuery = `
		DELETE FROM auth_tokens
		WHERE user_id = $1;
	`

	getRefreshTokenQuery = `
		SELECT refresh_token
		FROM auth_tokens
		WHERE user_id = $1;
	`

	updateRefreshTokenQuery = `
		UPDATE auth_tokens
		SET refresh_token = $1, updated_at = NOW(), created_at = $2
		WHERE user_id = $3;
	`
)

type repository struct {
	pool *pgxpool.Pool
}

func NewRepository(ctx context.Context, cfg config.PostgreSQL) (Repository, error) {
	connString := fmt.Sprintf(
		`user=%s password=%s host=%s port=%d dbname=%s sslmode=%s 
         pool_max_conns=%d pool_max_conn_lifetime=%s pool_max_conn_idle_time=%s`,
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
		cfg.SSLMode,
		cfg.PoolMaxConns,
		cfg.PoolMaxConnLifetime.String(),
		cfg.PoolMaxConnIdleTime.String(),
	)

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse PostgreSQL config")
	}

	poolConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PostgreSQL connection pool")
	}

	return &repository{pool: pool}, nil
}

func (r *repository) CreateUser(ctx context.Context, user *User) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx, createUserQuery, user.Username, user.HashedPassword, user.Email).Scan(&id)
	if err != nil {
		return 0, errors.Wrap(err, "failed to insert user")
	}
	return id, nil
}

func (r *repository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := r.pool.QueryRow(ctx, getUserByUsernameQuery, username).Scan(
		&user.ID,
		&user.Username,
		&user.HashedPassword,
		&user.Email,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user by username")
	}
	return &user, nil
}

func (r *repository) GetPassword(ctx context.Context, userID int64) (string, error) {
	var password string
	err := r.pool.QueryRow(ctx, getPasswordQuery, userID).Scan(&password)
	if err != nil {
		return "", errors.Wrap(err, "failed to get password")
	}
	return password, nil
}

func (r *repository) UpdatePassword(ctx context.Context, params UpdatePasswordParams) error {
	_, err := r.pool.Exec(ctx, updatePasswordQuery, params.Password, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to update password")
	}
	return nil
}

func (r *repository) NewRefreshToken(ctx context.Context, params NewRefreshTokenParams) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx, insertRefreshTokenQuery, params.UserID, params.Token).Scan(&id)
	if err != nil {
		return 0, errors.Wrap(err, "failed to insert refresh token")
	}
	return id, nil
}

func (r *repository) DeleteRefreshToken(ctx context.Context, params DeleteRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, deleteRefreshTokenQuery, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to delete refresh token")
	}
	return nil
}

func (r *repository) GetRefreshToken(ctx context.Context, params GetRefreshTokenParams) ([]string, error) {
	rows, err := r.pool.Query(ctx, getRefreshTokenQuery, params.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get refresh token")
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, errors.Wrap(err, "failed to scan refresh token")
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (r *repository) UpdateRefreshToken(ctx context.Context, params UpdateRefreshTokenParams) error {
	_, err := r.pool.Exec(ctx, updateRefreshTokenQuery, params.Token, params.CreatedDate, params.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to update refresh token")
	}
	return nil
}
