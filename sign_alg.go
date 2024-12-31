package primus

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"hash"
)

type EcdsaSignAlgT string

func (t EcdsaSignAlgT) String() string {
	return string(t)
}

var EcdsaSignAlg = struct {
	SHA1withECDSA   EcdsaSignAlgT
	SHA224withECDSA EcdsaSignAlgT
	SHA256withECDSA EcdsaSignAlgT
	SHA384withECDSA EcdsaSignAlgT
	SHA512withECDSA EcdsaSignAlgT
}{
	SHA1withECDSA:   "SHA1withECDSA",
	SHA224withECDSA: "SHA224withECDSA",
	SHA256withECDSA: "SHA256withECDSA",
	SHA384withECDSA: "SHA384withECDSA",
	SHA512withECDSA: "SHA512withECDSA",
}

var ecdsaObjects = []*ECDSAObject{
	NewECDSAObject(EcdsaSignAlg.SHA1withECDSA, []byte{42, 134, 72, 206, 61, 4, 1}, sha1.New),
	NewECDSAObject(EcdsaSignAlg.SHA224withECDSA, []byte{42, 134, 72, 206, 61, 4, 3, 1}, sha256.New224),
	NewECDSAObject(EcdsaSignAlg.SHA256withECDSA, []byte{42, 134, 72, 206, 61, 4, 3, 2}, sha256.New),
	NewECDSAObject(EcdsaSignAlg.SHA384withECDSA, []byte{42, 134, 72, 206, 61, 4, 3, 3}, sha512.New384),
	NewECDSAObject(EcdsaSignAlg.SHA512withECDSA, []byte{42, 134, 72, 206, 61, 4, 3, 4}, sha512.New),
}

type ECDSAObject struct {
	name   EcdsaSignAlgT
	oid    []byte
	hasher func() hash.Hash
}

func (o *ECDSAObject) Sign(priv *ecdsa.PrivateKey, input []byte) ([]byte, error) {
	var tmp [512]byte
	var h = o.hasher()
	h.Write(input)
	return ecdsa.SignASN1(rand.Reader, priv, h.Sum(tmp[:0]))
}

func (o *ECDSAObject) Verify(pub *ecdsa.PublicKey, input, sig []byte) bool {
	var tmp [512]byte
	var h = o.hasher()
	h.Write(input)
	return ecdsa.VerifyASN1(pub, h.Sum(tmp[:0]), sig)
}

func NewECDSAObject(name EcdsaSignAlgT, oid []byte, hasher func() hash.Hash) *ECDSAObject {
	return &ECDSAObject{name: name, oid: oid, hasher: hasher}
}

func finEcdsaNameByOid(oid []byte) EcdsaSignAlgT {
	for _, v := range ecdsaObjects {
		if subtle.ConstantTimeCompare(v.oid, oid) != 0 {
			return v.name
		}
	}
	return ""
}

func FindEcdsaByName(name EcdsaSignAlgT) *ECDSAObject {
	for _, v := range ecdsaObjects {
		if v.name == name {
			return v
		}
	}
	return nil
}
