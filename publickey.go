package primus

type Publickey interface {
	GetEncoded() []byte // return x509 format
}

type NamedPublicKey interface {
	Publickey
	GetName() string
}

func SerializePublicKey(pubkey Publickey, p *Payload) {
	var name = ""
	if v, ok := pubkey.(NamedPublicKey); ok {
		name = v.GetName()
	}
	if len(name) > 0 {
		p.addBs(LABEL_UTF8STRING, []byte(name))
	}
	p.addBs(PUBLIC_KEY_ENCODED, pubkey.GetEncoded())
}

type PublicKeyImpl struct {
	name string
	data []byte
}

func NewPublicKeyImpl(name string, data []byte) *PublicKeyImpl {
	return &PublicKeyImpl{name: name, data: data}
}

func (p *PublicKeyImpl) GetEncoded() []byte {
	return p.data
}

func (p *PublicKeyImpl) GetName() string {
	return p.name
}

func (p *PublicKeyImpl) DeSerialize(it *IterPart) {
	one := it.MustNext()
	if one.typ == LABEL_UTF8STRING {
		p.name = string(one.Data())
		one = it.MustNext()
	}
	if one.typ == PUBLIC_KEY_ENCODED {
		p.data = copySlice(one.Data())
	} else {
		it.Panic(one.typ, PUBLIC_KEY_ENCODED)
	}
}
