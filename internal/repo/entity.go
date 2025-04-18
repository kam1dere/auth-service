package repo

import (
	"database/sql"
	"time"
)

type User struct {
	ID             int64
	Username       string
	HashedPassword string
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type NewRefreshTokenParams struct {
	UserID int64
	Token  string
}

type DeleteRefreshTokenParams struct {
	UserID int64
}

type GetRefreshTokenParams struct {
	UserID int64
}

type UpdateRefreshTokenParams struct {
	UserID      int64
	Token       string
	CreatedDate sql.NullTime
}

type UpdatePasswordParams struct {
	UserID   int64
	Password string
}
