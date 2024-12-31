package primus

type PrimusSignature struct {
	signature     []byte
	signAlgorithm EcdsaSignAlgT
}

func NewPrimusSignature(signAlgorithm EcdsaSignAlgT, signature []byte) *PrimusSignature {
	return &PrimusSignature{signAlgorithm: signAlgorithm, signature: signature}
}

func (s *PrimusSignature) getEncodingWithSignAlgorithm() []byte {
	if isOidSig(s.signature) {
		return s.signature
	}
	return DerifyOidAndSig(s.signAlgorithm, s.signature)
}

func (s *PrimusSignature) Deserialize(bs []byte) {
	if isOidSig(bs) {
		s.signature = underifyOidAndSig(bs)
		s.signAlgorithm = extractSignAlgorithm(bs)
	} else {
		s.signAlgorithm = ""
		s.signature = bs
	}
}
