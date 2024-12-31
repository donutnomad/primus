package primus

import (
	"bytes"
	"testing"
)

func TestSignature(t *testing.T) {
	var sig = make([]byte, 32)
	fillByte(sig, 11)
	ret := NewPrimusSignature(EcdsaSignAlg.SHA256withECDSA, sig)

	bs := ret.getEncodingWithSignAlgorithm()

	out := new(PrimusSignature)
	out.Deserialize(bs)

	if out.signAlgorithm != ret.signAlgorithm {
		panic("invalid")
	}
	if !bytes.Equal(out.signature, ret.signature) {
		panic("invalid")
	}
	if !bytes.Equal(out.signature, sig) {
		panic("invalid")
	}
}
