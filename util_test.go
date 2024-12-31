package primus

import (
	"bytes"
	"encoding/hex"
	"github.com/samber/lo"
	"golang.org/x/crypto/cryptobyte/asn1"
	"testing"
)

func TestFindType(t *testing.T) {
	bs := lo.Must1(hex.DecodeString("3057300c06082a8648ce3d040302050003470030440220760d9ef0fae729dbdb73ff12ea58baa7b3ba116b7c53b963a195bcfc14b0a316022011b3ecd2f18b598a2f87e6c091efb740c7ceb9828551b64e48d36505267ee181"))
	oid := findType(bs, 0, int(asn1.OBJECT_IDENTIFIER))
	if !bytes.Equal(oid, []byte{42, 256 - 122, 72, 256 - 50, 61, 4, 3, 2}) {
		panic("invalid")
	}
	bitString := findType(bs, 0, int(asn1.BIT_STRING))
	if bitString == nil || hex.EncodeToString(bitString) != "0030440220760d9ef0fae729dbdb73ff12ea58baa7b3ba116b7c53b963a195bcfc14b0a316022011b3ecd2f18b598a2f87e6c091efb740c7ceb9828551b64e48d36505267ee181" {
		panic("invalid")
	}

	if finEcdsaNameByOid(oid) != "SHA256withECDSA" {
		panic("invalid")
	}
}

func TestDerifyOidAndSig(t *testing.T) {
	bs := lo.Must1(hex.DecodeString("30440220760d9ef0fae729dbdb73ff12ea58baa7b3ba116b7c53b963a195bcfc14b0a316022011b3ecd2f18b598a2f87e6c091efb740c7ceb9828551b64e48d36505267ee181"))
	ret := DerifyOidAndSig("SHA256withECDSA", bs)

	if hex.EncodeToString(ret) != "3057300c06082a8648ce3d040302050003470030440220760d9ef0fae729dbdb73ff12ea58baa7b3ba116b7c53b963a195bcfc14b0a316022011b3ecd2f18b598a2f87e6c091efb740c7ceb9828551b64e48d36505267ee181" {
		panic("invalid encode")
	}

	extractBs := underifyOidAndSig(ret)
	if !bytes.Equal(extractBs, bs) {
		panic("invalid decode")
	}
}

func mustDecode(hexStr string) []byte {
	return lo.Must1(hex.DecodeString(hexStr))
}
