package primus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/samber/lo"
)

type AccessGroup struct {
	Name       string      `json:"name"`
	Quorum     int         `json:"quorum"`
	PublicKeys []Publickey `json:"public_keys"`
}

func (g AccessGroup) MarshalJSON() ([]byte, error) {
	var obj = struct {
		Name       string   `json:"name"`
		Quorum     int      `json:"quorum"`
		PublicKeys []string `json:"public_keys"`
	}{
		Name:   g.Name,
		Quorum: g.Quorum,
		PublicKeys: lo.Map(g.PublicKeys, func(item Publickey, index int) string {
			return hex.EncodeToString(item.GetEncoded())
		}),
	}
	return json.Marshal(obj)
}

func (g *AccessGroup) Count(inputAsn1PubKey [][]byte) int {
	var count = 0
	var gPks = lo.Map(g.PublicKeys, func(item Publickey, index int) []byte {
		return item.GetEncoded()
	})
	for _, pk := range inputAsn1PubKey {
		if lo.ContainsBy(gPks, func(item []byte) bool {
			return bytes.Equal(item, pk)
		}) {
			count++
		}
	}
	return count
}

func (g *AccessGroup) Serialize(p *Payload) {
	if namingSupport && len(g.Name) > 0 {
		p.addBs(LABEL_UTF8STRING, []byte(g.Name))
	}
	p.addInt(SIGNATURES_REQUIRED, g.Quorum)
	p.addInt(KEYCOUNT_INT32, len(g.PublicKeys))
	for _, publicKey := range g.PublicKeys {
		SerializePublicKey(publicKey, p)
	}
}

func (g *AccessGroup) Deserialize(it *IterPart) (err error) {
	defer RecoverErr(&err)

	one := it.MustNext()
	if one.typ == LABEL_UTF8STRING {
		g.Name = string(one.Data())
		one = it.MustNext()
	}

	if one.typ == SIGNATURES_REQUIRED {
		g.Quorum = int(one.MustGetUint32())
	} else {
		it.Panic(one.typ, SIGNATURES_REQUIRED)
	}

	one = it.MustNext2(KEYCOUNT_INT32)
	g.PublicKeys = make([]Publickey, int(one.MustGetUint32()))
	for i := range g.PublicKeys {
		impl := new(PublicKeyImpl)
		impl.DeSerialize(it)
		g.PublicKeys[i] = impl
	}

	return nil
}
