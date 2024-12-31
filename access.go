package primus

type Access struct {
	Sign    []*AccessToken
	Block   []*AccessToken
	UnBlock []*AccessToken
	Modify  []*AccessToken
}

func NewAccess(signing, block, unBlock, modify []*AccessToken) *Access {
	return &Access{
		Sign:    signing,
		Block:   block,
		UnBlock: unBlock,
		Modify:  modify,
	}
}

func (a *Access) Blobs() []AccessBlob {
	var res = make([]AccessBlob, 4)
	res[0] = a.Sign
	res[1] = a.Block
	res[2] = a.UnBlock
	res[3] = a.Modify
	return res
}

func (a *Access) GetBlob(name BlobName) AccessBlob {
	switch name {
	case BlobNames.Signing:
		return a.Sign
	case BlobNames.Block:
		return a.Block
	case BlobNames.UnBlock:
		return a.UnBlock
	case BlobNames.Modify:
		return a.Modify
	default:
		panic("unreachable")
	}
}

func (a *Access) Serialize() []byte {
	var payload = Payload{}
	var blobs = []*AccessNamedBlob{
		NewPrimusAccessNamedBlob(BlobNames.Signing, a.Sign),
		NewPrimusAccessNamedBlob(BlobNames.Block, a.Block),
		NewPrimusAccessNamedBlob(BlobNames.UnBlock, a.UnBlock),
		NewPrimusAccessNamedBlob(BlobNames.Modify, a.Modify),
	}
	SerializeAll(blobs, &payload)
	return payload.Bytes()
}

func (a *Access) Deserialize(bs []byte) error {
	var payload = Payload{}
	err := payload.Deserialize(bs)
	if err != nil {
		return err
	}
	it := NewIterPart(payload.getParts())
	var blobs = make([]*AccessNamedBlob, 4)
	for i := 0; i < len(blobs); i++ {
		blob := new(AccessNamedBlob)
		if err = blob.Deserialize(it); err != nil {
			return err
		}
		if blob.Name == BlobNames.Signing {
			a.Sign = blob.Blob
		} else if blob.Name == BlobNames.Block {
			a.Block = blob.Blob
		} else if blob.Name == BlobNames.UnBlock {
			a.UnBlock = blob.Blob
		} else if blob.Name == BlobNames.Modify {
			a.Modify = blob.Blob
		}
		blobs[i] = blob
	}
	return nil
}

func (a *Access) ToModifyPayload() []byte {
	return lengthHeader(a.Serialize())
}
