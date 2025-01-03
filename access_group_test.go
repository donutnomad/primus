package primus

import (
	"encoding/json"
	"fmt"
	"github.com/samber/lo"
	"testing"
)

type BytesPublicKey []byte

func (b BytesPublicKey) GetEncoded() []byte {
	return b
}

func TestAccessGroupJsonMarshal(t *testing.T) {
	var a1 = []byte{1, 2, 3}
	var a2 = []byte{4, 5, 6}
	var a3 = []byte{7, 8, 9}
	var publicKeys = lo.Map([][]byte{a1, a2, a3}, func(item []byte, index int) Publickey {
		return BytesPublicKey(item)
	})
	var accessGroup = AccessGroup{
		Name:       "Test",
		Quorum:     2,
		PublicKeys: publicKeys,
	}
	marshal, err := json.Marshal(&accessGroup)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(string(marshal))
	if string(marshal) != "{\"name\":\"Test\",\"quorum\":2,\"public_keys\":[\"010203\",\"040506\",\"070809\"]}" {
		t.Fatal("failed")
	}
}

//func TestAccessGroup2(t *testing.T) {
//	AccessGroup
//}
