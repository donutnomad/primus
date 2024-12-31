package primus

import "encoding/binary"

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

func EncodePrimusTimestamp(payload []byte, signatureKeyName string, timeSeconds int64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(timeSeconds))

	var p2 = new(Payload)
	p2.addBs(60, nil)
	p2.addBs(EKA_SIGN_PAYLOAD, payload)
	p2.addBs(TIME_SECONDS_SINCE_EPOCH, tmp[:])
	p2.addBs(LABEL_UTF8STRING, []byte(signatureKeyName))
	return p2.Bytes()
}

func DecodePrimusTimestamp(timestamp []byte) (signatureKeyName string, seconds int64) {
	payload, err := optionallyCutLengthHeaderDecodePayload(timestamp)
	if err != nil {
		return "", 0
	}
	data := payload.findData(LABEL_UTF8STRING)
	signatureKeyName = string(data)
	data = payload.findData(TIME_SECONDS_SINCE_EPOCH)
	if len(data) >= 4 {
		seconds = int64(binary.LittleEndian.Uint32(data[:4]))
	}
	return signatureKeyName, seconds
}
