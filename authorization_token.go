package primus

import (
	"errors"
	"github.com/samber/lo"
)

type AuthorizationToken struct {
	data   []byte
	format string
}

type AuthorizationTokenImpl struct {
	DerSignatureBytes     []byte
	VerifySignatureBytes  []byte
	PublicKeyEncodedBytes []byte
	ApprovalTokenBytes    []byte
	ApprovalToken         *ApprovalToken
}

func NewPrimusAuthorizationToken(data []byte, format string) *AuthorizationToken {
	return &AuthorizationToken{data: data, format: format}
}

func NewPrimusAuthorizationTokenImpl(data []byte) (*AuthorizationTokenImpl, error) {
	payload, err := optionallyCutLengthHeaderDecodePayload(data)
	if err != nil {
		return nil, err
	}
	derSignatureBytes := payload.findData(DER_SIGNATURE)
	approvalTokenBytes := payload.findData(APPROVAL_TOKEN)
	tt := new(ApprovalToken)
	if err := tt.Deserialize(approvalTokenBytes); err != nil {
		return nil, err
	}
	ret := &AuthorizationTokenImpl{
		DerSignatureBytes:     derSignatureBytes,
		VerifySignatureBytes:  underifyOidAndSig(derSignatureBytes),
		PublicKeyEncodedBytes: payload.findData(PUBLIC_KEY_ENCODED),
		ApprovalTokenBytes:    approvalTokenBytes,
		ApprovalToken:         tt,
	}
	if len(ret.DerSignatureBytes) == 0 || len(ret.PublicKeyEncodedBytes) == 0 ||
		len(ret.VerifySignatureBytes) == 0 || len(ret.ApprovalTokenBytes) == 0 ||
		ret.ApprovalToken == nil {
		return nil, errors.New("invalid authorization token")
	}
	return ret, nil
}

// NewPrimusAuthorizationTokenEncode
// signature: ASN1 Format
// publicKey: ASN1 X509 Format
func NewPrimusAuthorizationTokenEncode(
	challenge []byte,
	signature []byte,
	signatureAlg EcdsaSignAlgT,
	publicKey []byte,
	certificateSupport bool,
) *AuthorizationToken {
	if len(signature) > 0 {
		signature = DerifyOidAndSig(signatureAlg, signature)
		if len(signature) == 0 {
			panic("invalid signature algorithm")
		}
	}
	var payload = new(Payload)
	if len(challenge) > 0 {
		payload.addBs(APPROVAL_TOKEN, challenge)
	}
	if len(signature) > 0 {
		payload.addBs(DER_SIGNATURE, signature)
	}
	if len(publicKey) > 0 {
		payload.addBs(lo.Ternary(certificateSupport, CERTIFICATEDATA_BYTES, PUBLIC_KEY_ENCODED), publicKey)
	}
	return NewPrimusAuthorizationToken(lengthHeader(payload.Bytes()), "")
}

func (t *AuthorizationToken) FindData(typ PayloadType) ([]byte, error) {
	payload, err := optionallyCutLengthHeaderDecodePayload(t.data)
	if err != nil {
		return nil, err
	}
	return payload.findData(typ), nil
}

func (t *AuthorizationToken) GetEncoding() []byte {
	return t.data
}

func (t *AuthorizationToken) GetFormat() string {
	return t.format
}

func (t *AuthorizationToken) GetDerSignatureBytes() ([]byte, error) {
	return t.FindData(DER_SIGNATURE)
}

func (t *AuthorizationToken) GetVerifySignatureBytes() ([]byte, error) {
	bs, err := t.GetDerSignatureBytes()
	if err != nil {
		return nil, err
	}
	return underifyOidAndSig(bs), nil
}

func (t *AuthorizationToken) GetPublicKeyEncodedBytes() ([]byte, error) {
	return t.FindData(PUBLIC_KEY_ENCODED)
}

func (t *AuthorizationToken) GetApprovalTokenBytes() ([]byte, error) {
	return t.FindData(APPROVAL_TOKEN)
}

func (t *AuthorizationToken) GetApprovalToken() (*ApprovalToken, error) {
	bs, err := t.GetApprovalTokenBytes()
	if err != nil {
		return nil, err
	}
	tt := new(ApprovalToken)
	if err := tt.Deserialize(bs); err != nil {
		return nil, err
	}
	return tt, nil
}
