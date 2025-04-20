package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/luizgbraga/crypto-go/internal/crypto"
	"github.com/luizgbraga/crypto-go/internal/crypto/rsa"
	"github.com/luizgbraga/crypto-go/internal/keystore"
	pb "github.com/luizgbraga/crypto-go/pkg/cryptogrpc"
	utils "github.com/luizgbraga/crypto-go/utils"
)

const (
	CmdListUsers   = "1"
	CmdManageKeys  = "2"
	CmdSendMessage = "3"
	CmdExit        = "4"
)

func mainMenu(client pb.CryptoServiceClient, keyStore keystore.KeyStore, rsaProvider *rsa.RSAProvider, userID string) {
	for {
		fmt.Println("\nCommands:")
		fmt.Printf("%s. List users\n", CmdListUsers)
		fmt.Printf("%s. Manage keys\n", CmdManageKeys)
		fmt.Printf("%s. Send message\n", CmdSendMessage)
		fmt.Printf("%s. Exit\n", CmdExit)

		cmd := utils.Read("Enter command: ")

		switch cmd {
		case CmdListUsers:
			listUsers(client)
		case CmdManageKeys:
			manageKeysMenu(client, keyStore, rsaProvider, userID)
		case CmdSendMessage:
			sendMessageMenu(client, rsaProvider, userID)
		case CmdExit:
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Unknown command")
		}
	}
}

const (
	DisplayKeyStore   = "1"
	CreateRSAKey      = "2"
	CmdManageKeysBack = "3"
)

func manageKeysMenu(client pb.CryptoServiceClient, keyStore keystore.KeyStore, rsaProvider *rsa.RSAProvider, userID string) {
	for {
		fmt.Println("\nKey Management Commands:")
		fmt.Printf("%s. Display key store\n", DisplayKeyStore)
		fmt.Printf("%s. Create RSA key\n", CreateRSAKey)
		fmt.Printf("%s. Back\n", CmdManageKeysBack)

		cmd := utils.Read("Enter command: ")

		switch cmd {
		case DisplayKeyStore:
			keyStore.Display()

		case CreateRSAKey:
			fmt.Println("Create RSA key")

			primeP, err := utils.ReadPrime("Enter prime P: ")
			if err != nil {
				fmt.Println("Error: ", err)
				continue
			}

			primeQ, err := utils.ReadPrime("Enter prime Q: ")
			if err != nil {
				fmt.Println("Error: ", err)
				continue
			}

			dOptions, err := rsaProvider.GetPossibleDValues(primeP, primeQ, 10)
			if err != nil {
				fmt.Printf("Error getting D values: %v\n", err)
				continue
			}

			fmt.Println("Suggested D values:")
			fmt.Println(strings.Join(dOptions, ", "))

			selectedD, err := utils.ReadBigInt("\nEnter D: ")
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}

			err = rsaProvider.ImportFromPrimes(primeP, primeQ, selectedD)
			if err != nil {
				fmt.Printf("Error creating key from primes: %v\n", err)
				continue
			}

			publicKeyBytes, err := rsaProvider.GetPublicKey()
			if err != nil {
				fmt.Printf("Error getting public key: %v\n", err)
				continue
			}

			resp, err := client.RegisterPublicKey(context.Background(), &pb.RegisterPublicKeyRequest{
				UserId:    userID,
				Algorithm: string(crypto.RSA),
				KeyData:   publicKeyBytes,
			})

			if err != nil {
				fmt.Printf("Error registering public key: %v\n", err)
				continue
			}

			if !resp.Success {
				fmt.Printf("Failed to register public key: %s\n", resp.Message)
				continue
			}

			fmt.Println("RSA key created successfully!")
		case CmdManageKeysBack:
			fmt.Println("Returning to main menu")
			return
		default:
			fmt.Println("Unknown command")
		}
	}
}

func sendMessageMenu(client pb.CryptoServiceClient, rsaProvider *rsa.RSAProvider, userID string) {
	for {
		fmt.Println("\nSend Message:")
		fmt.Println("(Enter 'back' to return to main menu)")

		recipient := utils.Read("Enter recipient ID: ")
		if recipient == "back" {
			return
		}

		_, err := rsaProvider.Encrypt([]byte("TEST"), recipient)
		if err != nil {
			resp, err := client.GetPublicKey(context.Background(), &pb.GetPublicKeyRequest{
				UserId:    recipient,
				Algorithm: string(crypto.RSA),
			})

			if err != nil || !resp.Success {
				fmt.Printf("Cannot send message: Unable to get recipient's public key\n")
				continue
			}

			err = rsaProvider.StorePublicKey(recipient, resp.KeyData)
			if err != nil {
				fmt.Printf("Error storing recipient's public key: %v\n", err)
				continue
			}
		}

		message := utils.Read("Enter message: ")
		if message == "back" {
			return
		}

		sendMessage(client, rsaProvider, userID, recipient, message)
	}
}
