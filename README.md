# Secure gRPC-based Messaging System

Crypto-gRPC is a secure messaging system built using gRPC for efficient communication that provides end-to-end encryption for messages using various cryptographic algorithms. 

## Algorithms

- [x] RSA
- [x] El Gamal
- [ ] ECC
- [ ] Lattice

## Architecture

The system is built using a microservices architecture with the following components:

- **gRPC Service**: Handles all communication between clients and the server
- **Crypto Service**: Manages cryptographic operations and key management
- **Message Service**: Handles message storage and delivery
