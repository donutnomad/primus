package primus

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/cryptobyte"
	asn1_ "golang.org/x/crypto/cryptobyte/asn1"
	"slices"
	"strconv"
)

func RecoverErr(mErr *error) {
	if err := recover(); err != nil {
		switch v := err.(type) {
		case error:
			*mErr = v
		case string:
			*mErr = errors.New(v)
		case int:
			*mErr = errors.New(strconv.Itoa(v))
		}
	}
}

func SerializeAll[E ~[]T, T interface {
	Serialize(p *Payload)
}](e E, p *Payload) {
	for _, item := range e {
		item.Serialize(p)
	}
}

func SerializeAllTag[E ~[]T, T interface {
	Serialize(p *Payload)
}](typ PayloadType, e E, p *Payload) {
	p.addInt(typ, len(e))
	for _, item := range e {
		item.Serialize(p)
	}
}

func DebugPrintPayload(bs []byte) {
	p, err := optionallyCutLengthHeaderDecodePayload(bs)
	if err != nil {
		panic(err)
	}
	spew.Dump(p)
}

func assert(b bool) {
	if !b {
		panic("assertion failed")
	}
}

func copySlice(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result
}

func lengthHeader(data []byte) []byte {
	return slices.Concat(LEUint32(len(data)), data)
}

func optionallyCutLengthHeader(data []byte) []byte {
	res, err := cutLengthHeader(data)
	if err != nil {
		return data
	}
	return res
}

func optionallyCutLengthHeaderDecodePayload(data []byte) (*Payload, error) {
	var p = new(Payload)
	return p, p.Deserialize(optionallyCutLengthHeader(data))
}

func cutLengthHeader(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("length header too short")
	}
	length := binary.LittleEndian.Uint32(data[:4])
	if int(length) != len(data)-4 {
		return nil, errors.New("data length doesn't match header")
	}
	return data[4:], nil
}

func LEUint32(i int) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(i))
	return b[:]
}

func isOidSig(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	ret, ni, err := parseTagAndLength(data, 0)
	if err != nil {
		return false
	}
	if ret.tag == asn1.TagSequence {
		ret, ni, err = parseTagAndLength(data, ni)
		if err != nil {
			return false
		}
		return ret.tag == asn1.TagSequence
	}
	return false
}

func underifyOidAndSig(data []byte) []byte {
	res := findType(data, 0, asn1.TagBitString)
	if len(res) > 0 {
		return res[1:]
	}
	return res
}

func DerifyOidAndSig(signAlgorithm EcdsaSignAlgT, sig []byte) []byte {
	obj := FindEcdsaByName(signAlgorithm)
	if obj == nil {
		panic("unreachable code")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1_.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1_.SEQUENCE, func(child *cryptobyte.Builder) {
			child.AddASN1(asn1_.OBJECT_IDENTIFIER, func(b *cryptobyte.Builder) {
				b.AddBytes(obj.oid)
			})
			child.AddASN1NULL()
		})
		b.AddASN1BitString(sig)
	})
	res, err := b.Bytes()
	if err != nil {
		return nil
	}
	return res
}

func extractSignAlgorithm(sig []byte) EcdsaSignAlgT {
	return finEcdsaNameByOid(findType(sig, 0, asn1.TagOID))
}

func ExtractSignAlgorithm(sig []byte) EcdsaSignAlgT {
	return finEcdsaNameByOid(findType(sig, 0, asn1.TagOID))
}

func fillByte(bs []byte, t int) {
	for i := range bs {
		bs[i] = byte(t)
	}
}

func findType(bs []byte, offset int, target int) []byte {
	for i := offset; i < len(bs); {
		ret, ni, err := parseTagAndLength(bs, i)
		if err != nil {
			return nil
		}
		i = ni
		if ret.tag == target {
			return bs[i : i+ret.length]
		} else if ret.tag == asn1.TagSequence {
			if ret := findType(bs, i, target); ret != nil {
				return ret
			}
		}
		i += ret.length
	}
	return nil
}

func FindTypeList(bs []byte, offset int, target int) [][]byte {
	var out [][]byte
	for i := offset; i < len(bs); {
		ret, ni, err := parseTagAndLength(bs, i)
		if err != nil {
			return nil
		}
		i = ni
		if ret.tag == target {
			out = append(out, bs[i:i+ret.length])
		} else if ret.tag == asn1.TagSequence {
			if ret := FindTypeList(bs, i, target); len(ret) > 0 {
				out = append(out, ret...)
			}
		}
		i += ret.length
	}
	return out
}
