package service

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/luizgbraga/crypto-go/internal/crypto"
	"github.com/luizgbraga/crypto-go/internal/keystore"
	pb "github.com/luizgbraga/crypto-go/pkg/cryptogrpc"
)

type CryptoServiceServer struct {
	pb.UnimplementedCryptoServiceServer
	users    map[string]*User
	keyStore *keystore.ServerKeyStore
	messages map[string][]*Message
	mutex    sync.Mutex
}

type User struct {
	ID       string
	Name     string
	Online   bool
	LastSeen time.Time
}

type Message struct {
	SenderID         string
	RecipientID      string
	EncryptedMessage []byte
	Algorithm        string
	Timestamp        time.Time
}

func NewCryptoServerServer() *CryptoServiceServer {
	return &CryptoServiceServer{
		users:    make(map[string]*User),
		keyStore: keystore.NewServerKeyStore(),
		messages: make(map[string][]*Message),
	}
}

func (s *CryptoServiceServer) RegisterUser(ctx context.Context, req *pb.RegisterUserRequest) (*pb.RegisterUserResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[req.UserId]; exists {
		return &pb.RegisterUserResponse{
			Success: false,
			Message: "User ID already exists",
		}, nil
	}

	s.users[req.UserId] = &User{
		ID:       req.UserId,
		Name:     req.Name,
		Online:   true,
		LastSeen: time.Now(),
	}

	log.Printf("User registered: %s (%s)", req.UserId, req.Name)
	return &pb.RegisterUserResponse{
		Success: true,
		Message: "User registered successfully",
	}, nil
}

func (s *CryptoServiceServer) GetUsers(ctx context.Context, req *pb.EmptyRequest) (*pb.UserList, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	userList := &pb.UserList{}
	for _, user := range s.users {
		userList.Users = append(userList.Users, &pb.User{
			UserId: user.ID,
			Name:   user.Name,
			Online: user.Online,
		})
	}

	return userList, nil
}

func (s *CryptoServiceServer) RegisterPublicKey(ctx context.Context, req *pb.RegisterPublicKeyRequest) (*pb.RegisterPublicKeyResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[req.UserId]; !exists {
		return &pb.RegisterPublicKeyResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	algorithm := crypto.Algorithm(req.Algorithm)
	err := s.keyStore.StorePublicKey(req.UserId, algorithm, req.KeyData)
	if err != nil {
		return &pb.RegisterPublicKeyResponse{
			Success: false,
			Message: "Failed to store public key: " + err.Error(),
		}, nil
	}

	log.Printf("Public key registered for user %s (algorithm: %s)", req.UserId, req.Algorithm)
	return &pb.RegisterPublicKeyResponse{
		Success: true,
		Message: "Public key registered successfully",
	}, nil
}

func (s *CryptoServiceServer) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[req.UserId]; !exists {
		return &pb.GetPublicKeyResponse{
			Success: false,
			Message: "User not found",
		}, nil
	}

	algorithm := crypto.Algorithm(req.Algorithm)
	keyData, err := s.keyStore.GetPublicKey(req.UserId, algorithm)
	if err != nil {
		return &pb.GetPublicKeyResponse{
			Success: false,
			Message: "Failed to get public key: " + err.Error(),
		}, nil
	}

	return &pb.GetPublicKeyResponse{
		Success: true,
		Message: "Public key retrieved successfully",
		KeyData: keyData,
	}, nil
}

func (s *CryptoServiceServer) SendMessage(ctx context.Context, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[req.SenderId]; !exists {
		return &pb.SendMessageResponse{
			Success: false,
			Message: "Sender not found",
		}, nil
	}

	if _, exists := s.users[req.RecipientId]; !exists {
		return &pb.SendMessageResponse{
			Success: false,
			Message: "Recipient not found",
		}, nil
	}

	message := &Message{
		SenderID:         req.SenderId,
		RecipientID:      req.RecipientId,
		EncryptedMessage: req.EncryptedMessage,
		Algorithm:        req.Algorithm,
		Timestamp:        time.Now(),
	}

	if _, exists := s.messages[req.RecipientId]; !exists {
		s.messages[req.RecipientId] = []*Message{}
	}
	s.messages[req.RecipientId] = append(s.messages[req.RecipientId], message)

	log.Printf("Message sent from %s to %s", req.SenderId, req.RecipientId)
	return &pb.SendMessageResponse{
		Success: true,
		Message: "Message sent successfully",
	}, nil
}

func (s *CryptoServiceServer) GetMessages(ctx context.Context, req *pb.GetMessagesRequest) (*pb.GetMessagesResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.users[req.UserId]; !exists {
		return &pb.GetMessagesResponse{}, nil
	}

	s.users[req.UserId].LastSeen = time.Now()
	s.users[req.UserId].Online = true

	userMessages, exists := s.messages[req.UserId]
	if !exists {
		return &pb.GetMessagesResponse{}, nil
	}

	protoMessages := make([]*pb.Message, 0, len(userMessages))
	for _, msg := range userMessages {
		protoMessages = append(protoMessages, &pb.Message{
			SenderId:         msg.SenderID,
			EncryptedMessage: msg.EncryptedMessage,
			Algorithm:        msg.Algorithm,
			Timestamp:        msg.Timestamp.Unix(),
		})
	}

	s.messages[req.UserId] = []*Message{}

	return &pb.GetMessagesResponse{
		Messages: protoMessages,
	}, nil
}
