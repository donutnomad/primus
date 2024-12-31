package primus

import (
	"errors"
	"fmt"
	"github.com/samber/lo"
)

type ApprovalTokenOpType int

func (t ApprovalTokenOpType) String() string {
	switch t {
	case ApprovalTokenOp.BLOCK:
		return "BLOCK"
	case ApprovalTokenOp.UNBLOCK:
		return "UNBLOCK"
	case ApprovalTokenOp.SIGN:
		return "SIGN"
	case ApprovalTokenOp.MODIFY:
		return "MODIFY"
	case ApprovalTokenOp.UNWRAP:
		return "UNWRAP"
	}
	return fmt.Sprintf("UNKNOWN(%d)", int(t))
}

func (t ApprovalTokenOpType) ToBlobName() BlobName {
	switch t {
	case ApprovalTokenOp.BLOCK:
		return BlobNames.Block
	case ApprovalTokenOp.UNBLOCK:
		return BlobNames.UnBlock
	case ApprovalTokenOp.SIGN:
		return BlobNames.Signing
	case ApprovalTokenOp.MODIFY:
		return BlobNames.Modify
	default:
		panic("unreachable")
	}
}

var ApprovalTokenOp = struct {
	UNWRAP  ApprovalTokenOpType
	BLOCK   ApprovalTokenOpType
	UNBLOCK ApprovalTokenOpType
	MODIFY  ApprovalTokenOpType
	SIGN    ApprovalTokenOpType
}{
	UNWRAP: 1,
	SIGN:   1,

	BLOCK:   2,
	UNBLOCK: 3,
	MODIFY:  4,
}

// Encoding:
//  (tool.PayloadPart) {
//   typ: (tool.PayloadType) 59, EkaOperation
//   data: ([]uint8) (len=4 cap=4) {
//    00000000  01 00 00 00                                       |....|
//   }
//  },
//  (tool.PayloadPart) {
//   typ: (tool.PayloadType) 4098, LABEL_UTF8STRING
//   data: ([]uint8) (len=8 cap=8) {
//    00000000  67 74 5f 65 63 5f 30 38                           |gt_ec_08|
//   }
//  },
//  (tool.PayloadPart) {
//   typ: (tool.PayloadType) 4180, EKA_TIME_STAMP
//   data: ([]uint8) (len=64 cap=64) {
//    00000000  3c 00 00 00 57 10 12 00  63 6f 6e 74 65 6e 74 20  |<...W...content |
//    00000010  74 6f 20 62 65 20 73 69  67 6e 00 00 07 01 08 00  |to be sign......|
//    00000020  c7 bf 15 67 00 00 00 00  02 10 14 00 67 6c 6f 62  |...g........glob|
//    00000030  61 6c 2d 69 6e 74 65 67  72 69 74 79 2d 6b 65 79  |al-integrity-key|
//   }
//  },
//  (tool.PayloadPart) {
//   typ: (tool.PayloadType) 4182, DER_SIGNATURE
//   data: ([]uint8) (len=90 cap=90) {
//    00000000  30 58 30 0c 06 08 2a 86  48 ce 3d 04 03 02 05 00  |0X0...*.H.=.....|
//    00000010  03 48 00 30 45 02 21 00  e6 06 46 98 d7 52 71 b4  |.H.0E.!...F..Rq.|
//    00000020  af 86 5f ff 86 94 1a 5a  80 83 af e7 bf ed 82 fd  |.._....Z........|
//    00000030  a3 50 1d 10 09 3a e0 3f  02 20 7e dc 8b c8 b7 6d  |.P...:.?. ~....m|
//    00000040  31 99 42 f2 9f 6b 90 54  63 4c 6c 55 96 a6 1b bc  |1.B..k.TcLlU....|
//    00000050  6c cf 4c 9e 26 c1 b4 0e  f6 81                    |l.L.&.....|
//   }
//  },
//  (tool.PayloadPart) {
//   typ: (tool.PayloadType) 4183, EKA_SIGN_PAYLOAD
//   data: ([]uint8) (len=18 cap=18) {
//    00000000  63 6f 6e 74 65 6e 74 20  74 6f 20 62 65 20 73 69  |content to be si|
//    00000010  67 6e                                             |gn|
//   }

type ApprovalToken struct {
	Operation          ApprovalTokenOpType
	EkaPayload         []byte
	KeyName            string
	Timestamp          []byte
	TimestampSignature *PrimusSignature
}

func NewPrimusApprovalTokenWithTime(operation ApprovalTokenOpType, ekaPayload []byte, keyName string, timestamp []byte, timestampSignature *PrimusSignature) *ApprovalToken {
	return &ApprovalToken{Operation: operation, EkaPayload: ekaPayload, KeyName: keyName, Timestamp: timestamp, TimestampSignature: timestampSignature}
}

func NewPrimusApprovalToken(operation ApprovalTokenOpType, ekaPayload []byte, keyName string) *ApprovalToken {
	return &ApprovalToken{Operation: operation, EkaPayload: ekaPayload, KeyName: keyName}
}

func (t *ApprovalToken) Serialize() []byte {
	var p = new(Payload)
	p.addInt(EKA_OPERATION, int(t.Operation))
	p.addBs(LABEL_UTF8STRING, []byte(t.KeyName))
	if len(t.Timestamp) > 0 {
		p.addBs(EKA_TIME_STAMP, t.Timestamp)
		if t.TimestampSignature != nil {
			p.addBs(DER_SIGNATURE, t.TimestampSignature.getEncodingWithSignAlgorithm())
		}
	}
	if len(t.EkaPayload) > 0 {
		p.addBs(lo.Ternary(t.Operation == ApprovalTokenOp.MODIFY, EKA_MODIFY_PAYLOAD, EKA_SIGN_PAYLOAD), t.EkaPayload)
	}
	return lengthHeader(p.Bytes())
}

func (t *ApprovalToken) Deserialize(bs []byte) error {
	p, err := optionallyCutLengthHeaderDecodePayload(bs)
	if err != nil {
		return err
	}
	var operation ApprovalTokenOpType = -1
	if pp := p.find(EKA_OPERATION); pp != nil {
		v, err := pp.GetUint32()
		if err != nil {
			return err
		}
		operation = ApprovalTokenOpType(v)
	}
	if pp := p.find(LABEL_UTF8STRING); pp != nil {
		t.KeyName = string(pp.data)
	}
	if pp := p.find(EKA_SIGN_PAYLOAD); pp != nil {
		t.EkaPayload = pp.Data()
	}
	if pp := p.find(EKA_MODIFY_PAYLOAD); pp != nil {
		t.EkaPayload = pp.Data()
	}
	if pp := p.find(EKA_TIME_STAMP); pp != nil {
		t.Timestamp = pp.Data()
	}
	if pp := p.find(DER_SIGNATURE); pp != nil {
		ps := new(PrimusSignature)
		ps.Deserialize(pp.Data())
		if len(ps.signature) > 0 {
			t.TimestampSignature = ps
		}
	}
	if operation == -1 {
		return errors.New("bad format")
	}
	t.Operation = operation
	return nil
}
