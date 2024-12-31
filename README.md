# Primus

[![Go Version](https://img.shields.io/badge/Go-1.23.1-blue.svg)](https://golang.org/doc/devel/release.html)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

A Go library for interacting with SecurSys Primus HSM (Hardware Security Module). This library provides cryptographic
authorization tokens and access control with ECDSA signatures for Primus HSM devices.

## 🚀 Features

- ECDSA signature generation and verification
- Authorization token management for Primus HSM
- Access control with quorum-based groups
- ASN.1 DER encoding/decoding
- Timestamp handling
- Public key management
- Blob-based access control
- Integration with Primus HSM devices

## 📦 Installation

```bash
go get github.com/donutnomad/primus
```

## 🔧 Requirements

- Go 1.23.1 or higher
- Access to a SecurSys Primus HSM device

## 🎯 Quick Start

```go
// Create a new authorization token for Primus HSM
token := NewPrimusAuthorizationTokenEncode(
challenge,
signature,
EcdsaSignAlg.SHA256withECDSA,
publicKey,
false,
)

// Verify signature
alg := ExtractSignAlgorithm(token.DerSignatureBytes)
ok := FindEcdsaByName(alg).Verify(pub, token.ApprovalTokenBytes, token.VerifySignatureBytes)
```

## 📚 Documentation

For Primus HSM product documentation, please refer to the official SecurSys documentation.

## 🧪 Testing

Run the test suite:

```bash
go test ./...
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped shape this project
- Special thanks to the Go crypto community
- SecurSys for their Primus HSM product