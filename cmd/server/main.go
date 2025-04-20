package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/luizgbraga/crypto-go/internal/service"
	pb "github.com/luizgbraga/crypto-go/pkg/cryptogrpc"
	"google.golang.org/grpc"
)

func main() {
	log.SetOutput(os.Stdout)
	log.Println("Starting Crypto gRPC server...")

	lis, err := net.Listen(("tcp"), ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Println("Listening on port 50051...")

	grpcServer := grpc.NewServer()

	cryptoService := service.NewCryptoServerServer()
	pb.RegisterCryptoServiceServer(grpcServer, cryptoService)

	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		log.Println("Shutting down gRPC server...")
		grpcServer.GracefulStop()
	}()

	log.Println("gRPC server started successfully.")

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
