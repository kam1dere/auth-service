package main

import (
	AuthService "auth-service/grpc/genproto"
	"auth-service/internal/config"
	"auth-service/internal/repo"
	"auth-service/internal/service"
	"auth-service/pkg/jwt"
	"auth-service/pkg/logger"
	"context"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	var cfg config.AppConfig
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	l, err := logger.NewLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to initialize l: %v", err)
	}
	defer l.Sync()

	ctx := context.Background()
	repository, err := repo.NewRepository(ctx, cfg.PostgreSQL)
	if err != nil {
		l.Fatalf("failed to initialize repository: %v", err)
	}

	privateKey, err := jwt.ReadPrivateKey()
	if err != nil {
		log.Fatal("failed to read private key")
	}
	publicKey, err := jwt.ReadPublicKey()
	if err != nil {
		log.Fatal("failed to read public key")
	}

	jwt := jwt.NewJWTClient(privateKey, publicKey, cfg.System.AccessTokenTimeout, cfg.System.RefreshTokenTimeout)

	authSrv := service.NewAuthServer(cfg, repository, jwt, l)

	grpcServer := grpc.NewServer()
	AuthService.RegisterAuthServiceServer(grpcServer, authSrv)

	lis, err := net.Listen("tcp", cfg.GRPC.ListenAddress)
	if err != nil {
		l.Fatalf("failed to listen on %s: %v", cfg.GRPC.ListenAddress, err)
	}

	go func() {
		l.Infof("gRPC server started on %s", cfg.GRPC.ListenAddress)
		if err := grpcServer.Serve(lis); err != nil {
			l.Fatalf("failed to serve: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	l.Info("Shutting down gRPC server...")
	grpcServer.GracefulStop()
}
