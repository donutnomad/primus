package primus

type PayloadType int

const EkaOperation PayloadType = 59
const TOKEN_COUNT PayloadType = 89
const LABEL_UTF8STRING PayloadType = 4098
const TIME_SECOND PayloadType = 86
const TIME_MINUTE PayloadType = 85
const GROUP_COUNT PayloadType = 90
const SIGNATURES_REQUIRED PayloadType = 91
const KEYCOUNT_INT32 PayloadType = 3
const PUBLIC_KEY_ENCODED PayloadType = 4178
const SIGN_BLOB PayloadType = 4174
const BLOCK_BLOB PayloadType = 4175
const UNBLOCK_BLOB PayloadType = 4176
const MODIFY_BLOB PayloadType = 4177

const EKA_OPERATION PayloadType = 59
const EKA_TIME_STAMP PayloadType = 4180
const DER_SIGNATURE PayloadType = 4182
const EKA_MODIFY_PAYLOAD PayloadType = 4184
const EKA_SIGN_PAYLOAD PayloadType = 4183
const APPROVAL_TOKEN PayloadType = 4181
const CERTIFICATEDATA_BYTES PayloadType = 4105
const TIME_SECONDS_SINCE_EPOCH PayloadType = 263

var namingSupport bool = true
var supportsSeconds bool = true
var serializeBlobAsOne = true

func SetProperty(_namingSupport bool, _supportsSeconds bool, _serializeBlobAsOne bool) {
	namingSupport = _namingSupport
	supportsSeconds = _supportsSeconds
	serializeBlobAsOne = _serializeBlobAsOne
}
