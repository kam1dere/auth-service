package service

import (
	AuthService "auth-service/grpc/genproto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

const (
	ErrUnknown                  = "try it a little later or check the data you entered"
	ErrUserAuthAlreadyExist     = "user auth already exist"
	ErrUserNotFound             = "User not found"
	ErrValidatePassword         = "Incorrect email or password. Number of attempts:"
	ErrValidateJwt              = "not authorized"
	ErrTokenNotFound            = "refresh token not found"
	ErrLockForCheckPassword     = "Exceeded the maximum number of attempts.\nTry again at"
	ErrPasswordMatchOldPassword = "Please enter new password"
)

func lockForActionErr(time time.Time) error {

	err := status.New(codes.Unavailable, ErrLockForCheckPassword)
	err, _ = err.WithDetails(&AuthService.Err{
		ExpirationTime: timestamppb.New(time),
	})
	return err.Err()
}
