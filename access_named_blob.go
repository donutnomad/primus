package primus

import (
	"encoding/binary"
	"errors"
)

type BlobName struct {
	name string
	typ  PayloadType
}

func (bn BlobName) Name() string {
	return bn.name
}
func (bn BlobName) String() string {
	return bn.name
}

var BlobNames = struct {
	Signing BlobName
	Block   BlobName
	UnBlock BlobName
	Modify  BlobName
}{
	Signing: BlobName{name: "Signing", typ: SIGN_BLOB},
	Block:   BlobName{name: "Block", typ: BLOCK_BLOB},
	UnBlock: BlobName{name: "Unblock", typ: UNBLOCK_BLOB},
	Modify:  BlobName{name: "ChangeAttributes", typ: MODIFY_BLOB},
}

type AccessNamedBlob struct {
	Name BlobName
	Blob AccessBlob
}

func NewPrimusAccessNamedBlob(name BlobName, blob AccessBlob) *AccessNamedBlob {
	return &AccessNamedBlob{Name: name, Blob: blob}
}

func (b *AccessNamedBlob) Serialize(p *Payload) {
	if serializeBlobAsOne {
		p2 := new(Payload)
		b.Blob.Serialize(p2)
		p.addBs(b.Name.typ, lengthHeader(p2.Bytes()))
	} else {
		b.Blob.Serialize(p)
	}
}

func (b *AccessNamedBlob) Deserialize(it *IterPart) (err error) {
	defer RecoverErr(&err)
	if serializeBlobAsOne {
		one := it.MustNext()
		switch one.typ {
		case SIGN_BLOB:
			b.Name = BlobNames.Signing
		case BLOCK_BLOB:
			b.Name = BlobNames.Block
		case UNBLOCK_BLOB:
			b.Name = BlobNames.UnBlock
		case MODIFY_BLOB:
			b.Name = BlobNames.Modify
		default:
			return errors.New("invalid blob type")
		}
		data := one.Data()
		if len(data) < 4 {
			return errors.New("invalid blob size")
		}
		size := binary.LittleEndian.Uint32(data[:4])
		if int(size) != len(data[4:]) {
			return errors.New("invalid blob size")
		}
		payload2 := new(Payload)
		err := payload2.Deserialize(data[4:])
		if err != nil {
			return err
		}
		itt := NewIterPart(payload2.getParts())
		return b.Blob.Deserialize(itt)
	} else {
		return b.Blob.Deserialize(it)
	}
}

type AccessBlob []*AccessToken

func (b *AccessBlob) ContainPublicKey(p []byte) bool {
	for _, token := range *b {
		for _, group := range token.Groups {
			if group.Count([][]byte{p}) > 0 {
				return true
			}
		}
	}
	return false
}

func (b *AccessBlob) Serialize(p *Payload) {
	SerializeAllTag(TOKEN_COUNT, *b, p)
}

func (b *AccessBlob) Deserialize(it *IterPart) (err error) {
	defer RecoverErr(&err)
	count := it.MustNext2(TOKEN_COUNT).MustGetUint32()
	var tokens = make([]*AccessToken, count)
	for i := range tokens {
		tokens[i] = new(AccessToken)
		if err := tokens[i].Deserialize(it); err != nil {
			return err
		}
	}
	*b = tokens
	return nil
}
