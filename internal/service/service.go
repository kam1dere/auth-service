package service

import (
	AuthService "auth-service/grpc/genproto"
	"auth-service/internal/config"
	"auth-service/internal/repo"
	"auth-service/pkg/jwt"
	"auth-service/pkg/secure"
	"auth-service/pkg/validator"
	"context"
	"database/sql"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strconv"
	"time"
)

type authServer struct {
	cfg                   config.AppConfig
	repo                  repo.Repository
	log                   *zap.SugaredLogger
	jwt                   jwt.JWTClient
	numberPasswordEntries *cache.Cache
	AuthService.UnimplementedAuthServiceServer
}

func NewAuthServer(cfg config.AppConfig, repo repo.Repository, jwt jwt.JWTClient, log *zap.SugaredLogger) AuthService.AuthServiceServer {
	return &authServer{
		cfg:  cfg,
		repo: repo,
		log:  log,
		jwt:  jwt,
		numberPasswordEntries: cache.New(
			cfg.System.LockPasswordEntry,
			cfg.System.LockPasswordEntry,
		),
	}
}

func (a *authServer) Register(ctx context.Context, req *AuthService.RegisterRequest) (*AuthService.RegisterResponse, error) {
	if err := validator.Validate(ctx, req); err != nil {
		a.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	passwordValidityCheck, err := secure.IsValidPassword(req.Password)

	if !passwordValidityCheck {

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	req.Password, _ = secure.HashPassword(req.Password)

	_, err = a.repo.CreateUser(ctx, &repo.User{
		Username:       req.GetUsername(),
		HashedPassword: req.GetPassword(),
		Email:          req.GetEmail(),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.UniqueViolation {
				return nil, status.Error(codes.AlreadyExists, ErrUserAuthAlreadyExist)
			}
		}

		return nil, errors.Wrap(err, "failed to create user")
	}

	return &AuthService.RegisterResponse{}, nil
}

func (a *authServer) Login(ctx context.Context, req *AuthService.LoginRequest) (*AuthService.LoginResponse, error) {
	if err := validator.Validate(ctx, req); err != nil {
		a.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	user, err := a.repo.GetUserByUsername(ctx, req.GetUsername())
	if err != nil {
		a.log.Errorf("failed to get credentials for user %a: %v", req.GetUsername(), err)

		return nil, status.Error(codes.NotFound, "user not found")
	}

	if err := secure.CheckPassword(user.HashedPassword, req.GetPassword()); err != nil {
		a.log.Errorf("invalid password for user %a: %v", req.GetUsername(), err)

		return nil, status.Error(codes.Unauthenticated, "invalid username or password")
	}

	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: user.ID,
	})

	if err != nil {
		a.log.Errorf("failed to generate access token for user %a: %v", req.GetUsername(), err)

		return nil, errors.Wrap(err, "failed to generate token")
	}

	return &AuthService.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *authServer) UpdatePassword(
	ctx context.Context,
	req *AuthService.UpdatePasswordRequest,
) (
	*AuthService.UpdatePasswordResponse, error,
) {

	remainingAttempts, err := a.checkRemainingAttempts(req.UserId)
	if err != nil {
		return nil, err
	}

	passwordValidityCheck, err := secure.IsValidPassword(req.NewPassword)

	if !passwordValidityCheck {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	password, err := a.repo.GetPassword(ctx, req.UserId)
	if err != nil {
		if err == sql.ErrNoRows {

			return nil, status.Error(codes.NotFound, ErrUserNotFound)
		}

		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	err = secure.CheckPassword(password, req.Password)

	if req.Password != "" && err != nil {
		a.numberPasswordEntries.Set(strconv.FormatInt(req.UserId, 10), remainingAttempts-1, cache.DefaultExpiration)

		return nil, status.Errorf(
			codes.InvalidArgument,
			"%s %d",
			ErrValidatePassword,
			remainingAttempts-1,
		)
	}

	err = secure.CheckPassword(password, req.NewPassword)
	if err == nil {
		return nil, status.Error(codes.InvalidArgument, ErrPasswordMatchOldPassword)
	}

	req.NewPassword, _ = secure.HashPassword(req.NewPassword)

	err = a.repo.UpdatePassword(ctx, repo.UpdatePasswordParams{
		Password: req.NewPassword,
		UserID:   req.UserId,
	})
	if err != nil {

		return nil, status.Errorf(codes.Internal, ErrUnknown)
	}

	a.numberPasswordEntries.Delete(strconv.FormatInt(req.UserId, 10))

	return &AuthService.UpdatePasswordResponse{}, nil
}

func (a *authServer) checkRemainingAttempts(userId int64) (int64, error) {

	remainingAttempts := a.cfg.System.NumberPasswordAttempts
	remainingAttemptsFromCache, expirationTime, ok := a.numberPasswordEntries.GetWithExpiration(strconv.FormatInt(userId, 10))

	if ok && remainingAttemptsFromCache.(int64) == 0 {
		return 0, lockForActionErr(expirationTime)
	}
	if ok {
		remainingAttempts = remainingAttemptsFromCache.(int64)
	}
	return remainingAttempts, nil

}

func (a *authServer) Validate(
	ctx context.Context,
	req *AuthService.ValidateRequest,
) (
	*AuthService.ValidateResponse, error,
) {

	check, err := a.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	if !check {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	accessData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	_, err = a.repo.GetRefreshToken(ctx, repo.GetRefreshTokenParams{
		UserID: accessData.UserId,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
		}

		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.ValidateResponse{
		UserId: accessData.UserId,
	}, nil
}

func (a *authServer) NewJwt(
	ctx context.Context,
	req *AuthService.NewJwtRequest,
) (
	*AuthService.NewJwtResponse, error,
) {

	if err := validator.Validate(ctx, req); err != nil {
		a.log.Errorf("validation error: %v", err)

		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: req.UserId,
	})

	if err != nil {
		a.log.Errorf("create tokens err: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	_, err = a.repo.NewRefreshToken(ctx, repo.NewRefreshTokenParams{
		UserID: req.UserId,
		Token:  tokens.RefreshToken,
	})

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == pgerrcode.ForeignKeyViolation {
				return nil, status.Error(codes.NotFound, ErrUserNotFound)
			}
		}
		a.log.Errorf("adding a token to the database: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.NewJwtResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *authServer) RevokeJwt(
	ctx context.Context,
	req *AuthService.RevokeJwtRequest,
) (
	*AuthService.RevokeJwtResponse, error,
) {

	err := a.repo.DeleteRefreshToken(ctx, repo.DeleteRefreshTokenParams{
		UserID: req.UserId,
	})
	if err != nil {
		a.log.Errorf("remove a token to the database: user_id = %d", req.UserId)
		return nil, status.Error(codes.Internal, ErrUnknown)
	}
	return &AuthService.RevokeJwtResponse{}, nil
}

func (a *authServer) Refresh(
	ctx context.Context,
	req *AuthService.RefreshRequest,
) (
	*AuthService.RefreshResponse, error,
) {

	check, err := a.jwt.ValidateToken(&jwt.ValidateTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil {
		a.log.Errorf("validate refresh token err")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	if !check {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	accessData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.AccessToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	refreshData, err := a.jwt.GetDataFromToken(&jwt.GetDataFromTokenParams{
		Token: req.RefreshToken,
	})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}
	if accessData.UserId != refreshData.UserId {
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	rtToken, err := a.repo.GetRefreshToken(ctx, repo.GetRefreshTokenParams{
		UserID: refreshData.UserId,
	})
	if err != nil {
		a.log.Errorf("get refresh token err")
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.NotFound, ErrTokenNotFound)
		}
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	if len(rtToken) == 0 {
		a.log.Errorf("len(rtToken) == 0")
		return nil, status.Error(codes.NotFound, ErrTokenNotFound)
	}

	if rtToken[0] != req.RefreshToken {
		a.log.Errorf("rtToken[0] != req.RefreshToken")
		return nil, status.Error(codes.Unauthenticated, ErrValidateJwt)
	}

	tokens, err := a.jwt.CreateToken(&jwt.CreateTokenParams{
		UserId: refreshData.UserId,
	})

	if err != nil {
		a.log.Errorf("create tokens error")
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	err = a.repo.UpdateRefreshToken(ctx, repo.UpdateRefreshTokenParams{
		Token:       tokens.RefreshToken,
		CreatedDate: sql.NullTime{Time: time.Now(), Valid: true},
		UserID:      refreshData.UserId,
	})

	if err != nil {
		a.log.Errorf("update refresh token err")
		return nil, status.Error(codes.Internal, ErrUnknown)
	}

	return &AuthService.RefreshResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
