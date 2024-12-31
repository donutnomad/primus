package primus

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/donutnomad/blockchain-alg/xx509"
	"github.com/samber/lo"
	"testing"
)

func TestCheck(t *testing.T) {
	authorizationTokenBs := mustDecode("f4000000551030002c0000003b000400010000000210080067745f65635f303857101200636f6e74656e7420746f206265207369676e000056105a003058300c06082a8648ce3d04030205000348003045022100d795ee0d3b53f3474f0b96d2963577ee1299c40bcdcbe221de72b3d8c735f4e202204834dd924a200348c93afa5ab2bc59e84faa8ad7bad1c378eac9406418fb9ea3000052105b003059301306072a8648ce3d020106082a8648ce3d03010703420004b72d37ba3ca4b9f3406fcbca53b9a6cc051c2a9763c22859466f5b36ace044ce7d26a4cfabfbe2e9a147c51ab73732bdd0b8e9e7310861863999eb82590151c900")

	var payload []byte
	token := lo.Must1(NewPrimusAuthorizationTokenImpl(authorizationTokenBs))
	approvalToken := token.ApprovalToken
	if approvalToken.Operation != ApprovalTokenOp.SIGN {
		panic("must be SIGN")
	}
	if !bytes.Equal(approvalToken.EkaPayload, payload) {
		//panic("not equal")
	}
	alg := ExtractSignAlgorithm(token.DerSignatureBytes)
	if alg == "" {
		panic("parse algorithm failed")
	}

	pubKey, err := xx509.ParsePKIXPublicKey(token.PublicKeyEncodedBytes)
	if err != nil {
		return
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		panic("not ecdsa public key")
	}

	fmt.Println("Algorithm")
	spew.Dump(pub)

	ok = FindEcdsaByName(alg).Verify(pub, token.ApprovalTokenBytes, token.VerifySignatureBytes)
	fmt.Println("Result:", ok)
}

func Test002(t *testing.T) {
	approvalTokenBs := mustDecode("d00000003b000400010000000210080067745f65635f3038541040003c00000057101200636f6e74656e7420746f206265207369676e00000701080038db15670000000002101400676c6f62616c2d696e746567726974792d6b657956105a003058300c06082a8648ce3d0403020500034800304502206a1682a7afac732ab4ab7f9576ff70880b8414d3ff04448778e1b6ebb877a3d4022100b7b004e29f23454ab13dc73ec0aa70d9b428d656b35465dc6cbaefe38e338a58000057101200636f6e74656e7420746f206265207369676e0000")

	var tt = new(ApprovalToken)
	err := tt.Deserialize(approvalTokenBs)
	if err != nil {
		panic(err)
	}
	spew.Dump(tt)
	DebugPrintPayload(tt.Timestamp)

	bs2 := NewPrimusApprovalTokenWithTime(
		tt.Operation,
		tt.EkaPayload,
		tt.KeyName,
		tt.Timestamp,
		tt.TimestampSignature,
	).Serialize()

	spew.Dump(tt.Timestamp)
	spew.Dump(tt.TimestampSignature)
	if !bytes.Equal(approvalTokenBs, bs2) {
		panic("invalid")
	}

	// Struct：
	// (tool.PayloadPart) {
	//   typ: (tool.PayloadType) 60,  APPROVAL_COUNT
	//   data: ([]uint8) {
	//   }
	//  },
	//  (tool.PayloadPart) {
	//   typ: (tool.PayloadType) 4183, EKA_SIGN_PAYLOAD
	//   data: ([]uint8) (len=18 cap=18) {
	//    00000000  63 6f 6e 74 65 6e 74 20  74 6f 20 62 65 20 73 69  |content to be si|
	//    00000010  67 6e                                             |gn|
	//   }
	//  },
	//  (tool.PayloadPart) {
	//   typ: (tool.PayloadType) 263, TIME_SECONDS_SINCE_EPOCH
	//   data: ([]uint8) (len=8 cap=8) {
	//    00000000  c7 bf 15 67 00 00 00 00                           |...g....|
	//   }
	//  },
	//  (tool.PayloadPart) {
	//   typ: (tool.PayloadType) 4098, LABEL_UTF8STRING
	//   data: ([]uint8) (len=20 cap=20) {
	//    00000000  67 6c 6f 62 61 6c 2d 69  6e 74 65 67 72 69 74 79  |global-integrity|
	//    00000010  2d 6b 65 79                                       |-key|
	//   }
	//  }
}

func TestCheck2(t *testing.T) {
	var DonAsn2PubKey = mustDecode("3059301306072a8648ce3d020106082a8648ce3d03010703420004b72d37ba3ca4b9f3406fcbca53b9a6cc051c2a9763c22859466f5b36ace044ce7d26a4cfabfbe2e9a147c51ab73732bdd0b8e9e7310861863999eb82590151c9")
	//var DonAsn2PubKey = mustDecode("302a300506032b656e032100e134a601c0fae8aabf3e2ed4485ad556e9f4e77cdd61aef0551bc8bd94f11004")
	spew.Dump(DonAsn2PubKey)
	var cert = lo.Must1(x509.ParsePKIXPublicKey(DonAsn2PubKey))
	spew.Dump(cert)

	bs2 := lo.Must1(base64.StdEncoding.DecodeString("MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuiW6iumaFdLz8hZgvkvltYT9zROMRrfL46RqY4CmHP/oSP0NS8kZuYZjeXYzAYtn0k1v8/8KcojhfI6q4AT7ng=="))
	var cert2 = lo.Must1(xx509.ParsePKIXPublicKey(bs2))
	spew.Dump(cert2)
}
