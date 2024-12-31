package primus

type KeyAttributeT struct {
	Name string
	typ  int
	flag int
}

func DefaultKeyAttribute() map[KeyAttributeT]bool {
	return map[KeyAttributeT]bool{
		KeyAttribute.AccessExtractable: false,
		KeyAttribute.AccessSensitive:   true,
		KeyAttribute.AccessModifiable:  true,
	}
}

func (t KeyAttributeT) HasFlag(flags int) bool {
	return flags&t.flag == t.flag
}

func (t KeyAttributeT) Flag() int {
	return t.flag
}
func (t KeyAttributeT) IsAccess() bool {
	return t.typ == 1
}
func (t KeyAttributeT) IsCapability() bool {
	return t.typ == 2
}

var capabilityFlags = []KeyAttributeT{
	KeyAttribute.CapabilitySign,
	KeyAttribute.CapabilityDecrypt,
	KeyAttribute.CapabilityDerive,
	KeyAttribute.CapabilityIntegrity,
}

var KeyAttribute = struct {
	// Public key can verify signatures, default is true
	CapabilitySign KeyAttributeT
	// Key or public key can encrypt data, default is true
	CapabilityDecrypt KeyAttributeT
	// Key can be used for derivation, i.e. using key agreement schemes (e.g. DH) or hierarchical deterministic keys. Default is true
	CapabilityDerive KeyAttributeT
	// Key can be used as an integrity key, also for signing HSM timestamps. Default is false
	CapabilityIntegrity KeyAttributeT

	// Key is always sensitive
	AccessAlwaysSensitive KeyAttributeT
	// Public key will not be revealed before first signing operation. Useful for cryptocurrencies and blockchain, and quantum computing issues. Default is false. If this flag is set, cryptocurrency type is required at creation
	AccessNoPublicKey KeyAttributeT
	// PKCS#11 flag (used with PKCS#11 API): accessing private key does not require PKCS#11 PIN login
	// ACCESS_PUBLIC(2, PrimusKeyAttributes.ACCESS_PUBLIC),
	// 	ACCESS_PRIVATE
	// PKCS#11 flag (used with PKCS#11 API): accessing public key also requires PKCS#11 PIN login
	// Key is blocked from use (signing etc). Default is false
	AccessBlocked KeyAttributeT
	// Key cannot be deleted (must delete HSM partition to remove it). (Use with caution when testing.) Default is false
	AccessIndestructible KeyAttributeT
	// Key is actually persistent, even after logout/roll. Default is true. HSM firmware may not support non-token keys/session keys
	AccessToken KeyAttributeT
	// Key can be copied. Default depends on HSM firmware version
	AccessCopyable KeyAttributeT
	// Key can be extracted. See #ACCESS_SENSITIVE if wrapped or plaintext only. Default is false. Policy on HSM may disable extractability
	AccessExtractable KeyAttributeT
	// Key is sensitive. If key is fully extractable, only allows extraction via wrapping. Default is true. Policy on HSM may disable extractability
	AccessSensitive KeyAttributeT
	// Key flags can be (partially) modified. Default is true. ACCESS_MODIFIABLE obviously cannot be changed later from false to true
	AccessModifiable KeyAttributeT
}{
	CapabilitySign:      KeyAttributeT{"CAPABILITY_SIGN", 1, 4},
	CapabilityDecrypt:   KeyAttributeT{"CAPABILITY_DECRYPT", 1, 2},
	CapabilityDerive:    KeyAttributeT{"CAPABILITY_DERIVE", 1, 64},
	CapabilityIntegrity: KeyAttributeT{"CAPABILITY_INTEGRITY", 1, 128},

	AccessAlwaysSensitive: KeyAttributeT{"ACCESS_ALWAYS_SENSITIVE", 2, 4096},
	AccessNoPublicKey:     KeyAttributeT{"ACCESS_NO_PUBLIC_KEY", 2, 2048},
	AccessBlocked:         KeyAttributeT{"ACCESS_BLOCKED", 2, 512},
	AccessIndestructible:  KeyAttributeT{"ACCESS_INDESTRUCTIBLE", 2, 64},
	AccessToken:           KeyAttributeT{"ACCESS_TOKEN", 2, 32},
	AccessCopyable:        KeyAttributeT{"ACCESS_COPYABLE", 2, 8},
	AccessExtractable:     KeyAttributeT{"ACCESS_EXTRACTABLE", 2, 2},
	AccessSensitive:       KeyAttributeT{"ACCESS_SENSITIVE", 2, 1},
	AccessModifiable:      KeyAttributeT{"ACCESS_MODIFIABLE", 2, 4},
}
