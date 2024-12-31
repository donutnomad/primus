package primus

import "strings"

type KeyAlgT string

func (t KeyAlgT) String() string {
	return string(t)
}

func (t *KeyAlgT) FromString(s string) bool {
	switch KeyAlgT(s) {
	case KeyAlg.SECP224R1:
		*t = KeyAlg.SECP224R1
	case KeyAlg.SECP256K1:
		*t = KeyAlg.SECP256K1
	case KeyAlg.SECP256R1:
		*t = KeyAlg.SECP256R1
	case KeyAlg.SECP384R1:
		*t = KeyAlg.SECP384R1
	case KeyAlg.SECP521R1:
		*t = KeyAlg.SECP521R1
	case KeyAlg.ED25519:
		*t = KeyAlg.ED25519
	case KeyAlg.X25519:
		*t = KeyAlg.X25519
	case "X25519":
		*t = KeyAlg.X25519
	default:
		*t = ""
		return false
	}
	return true
}

func (t *KeyAlgT) IsRsSignature() bool {
	return strings.HasPrefix(t.String(), "SECP") || *t == KeyAlg.ED25519 || *t == KeyAlg.X25519
}

var KeyAlg = struct {
	SECP224R1 KeyAlgT // P-224
	SECP256K1 KeyAlgT
	SECP256R1 KeyAlgT // P-256
	SECP384R1 KeyAlgT // P-384
	SECP521R1 KeyAlgT // P-521
	ED25519   KeyAlgT
	X25519    KeyAlgT
}{
	SECP224R1: "SECP224R1",
	SECP256K1: "SECP256K1",
	SECP256R1: "SECP256R1",
	SECP384R1: "SECP384R1",
	SECP521R1: "SECP521R1",
	ED25519:   "ED25519",
	X25519:    "CURVE25519",
}
