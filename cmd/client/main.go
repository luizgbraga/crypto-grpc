package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/luizgbraga/crypto-go/internal/crypto"
	"github.com/luizgbraga/crypto-go/internal/crypto/elgamal"
	"github.com/luizgbraga/crypto-go/internal/crypto/rsa"
	"github.com/luizgbraga/crypto-go/internal/keystore"
	pb "github.com/luizgbraga/crypto-go/pkg/cryptogrpc"
	reader "github.com/luizgbraga/crypto-go/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.NewClient("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewCryptoServiceClient(conn)
	userID, name := getUser()

	keyStore := keystore.NewClientKeyStore(userID)

	rsaProvider := rsa.NewRSAProvider(keyStore, userID)
	elgamalProvider := elgamal.NewElGamalProvider(keyStore, userID)

	resp, err := client.RegisterUser(context.Background(), &pb.RegisterUserRequest{
		UserId: userID,
		Name:   name,
	})
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}
	if !resp.Success {
		log.Fatalf("Registration failed: %s", resp.Message)
	}
	fmt.Println("User registered!")

	go pollForMessages(client, userID, rsaProvider)

	mainMenu(client, keyStore, rsaProvider, elgamalProvider, userID)
}

func getUser() (string, string) {
	userID := reader.Read("Enter your ID: ")
	name := reader.Read("Enter your name: ")

	return userID, name
}

func pollForMessages(client pb.CryptoServiceClient, userID string, rsaProvider *rsa.RSAProvider) {
	for {
		resp, err := client.GetMessages(context.Background(), &pb.GetMessagesRequest{
			UserId: userID,
		})
		if err == nil && len(resp.Messages) > 0 {
			fmt.Printf("\nYou have %d new message(s)!\n", len(resp.Messages))
			for _, msg := range resp.Messages {
				handleIncomingMessage(msg, rsaProvider)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func handleIncomingMessage(msg *pb.Message, rsaProvider *rsa.RSAProvider) {
	fmt.Printf("\nNew message from %s:\n", msg.SenderId)

	decrypted, err := rsaProvider.Decrypt(msg.EncryptedMessage)
	if err != nil {
		fmt.Printf("Failed to decrypt message: %v\n", err)
		return
	}

	fmt.Printf("Message: %s\n", decrypted)
}

func listUsers(client pb.CryptoServiceClient) {
	users, err := client.GetUsers(context.Background(), &pb.EmptyRequest{})
	if err != nil {
		fmt.Printf("Error listing users: %v\n", err)
		return
	}

	fmt.Println("\nUsers:")
	for _, user := range users.Users {
		status := "offline"
		if user.Online {
			status = "online"
		}
		fmt.Printf("- %s (%s): %s\n", user.UserId, user.Name, status)
	}
}

func sendRSAEncryptedMessage(client pb.CryptoServiceClient, rsaProvider *rsa.RSAProvider, userID, recipientID, message string) {
	encrypted, err := rsaProvider.Encrypt([]byte(message), recipientID)
	if err != nil {
		fmt.Printf("Error encrypting message: %v\n", err)
		return
	}

	resp, err := client.SendMessage(context.Background(), &pb.SendMessageRequest{
		SenderId:         userID,
		RecipientId:      recipientID,
		EncryptedMessage: encrypted,
		Algorithm:        string(crypto.RSA),
	})

	if err != nil {
		fmt.Printf("Error sending message: %v\n", err)
		return
	}

	if !resp.Success {
		fmt.Printf("Failed to send message: %s\n", resp.Message)
		return
	}

	fmt.Println("Message sent successfully!")
}

func sendElGamalEncryptedMessage(client pb.CryptoServiceClient, elgamalProvider *elgamal.ElGamalProvider, userID, recipientID, message string, k big.Int) {
	encrypted, err := elgamalProvider.Encrypt([]byte(message), recipientID, k)
	if err != nil {
		fmt.Printf("Error encrypting message: %v\n", err)
		return
	}

	resp, err := client.SendMessage(context.Background(), &pb.SendMessageRequest{
		SenderId:         userID,
		RecipientId:      recipientID,
		EncryptedMessage: encrypted,
		Algorithm:        string(crypto.ElGamal),
	})

	if err != nil {
		fmt.Printf("Error sending message: %v\n", err)
		return
	}

	if !resp.Success {
		fmt.Printf("Failed to send message: %s\n", resp.Message)
		return
	}

	fmt.Println("Message sent successfully!")
}
