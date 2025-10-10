package types

// SecureValue is a wrapper for sensitive byte data that ensures memory cleanup
// This type helps prevent sensitive data from remaining in memory after use
type SecureValue struct {
	data []byte
}

// NewSecureValue creates a new SecureValue from a byte slice
// The data is copied to prevent external modifications
func NewSecureValue(data []byte) *SecureValue {
	if data == nil {
		return &SecureValue{data: nil}
	}
	cpy := make([]byte, len(data))
	copy(cpy, data)
	return &SecureValue{
		data: cpy,
	}
}

// Bytes returns a copy of the value as a byte slice
func (sv *SecureValue) Bytes() []byte {
	if sv == nil || sv.data == nil {
		return nil
	}
	// Return a copy to prevent external modifications
	cpy := make([]byte, len(sv.data))
	copy(cpy, sv.data)
	return cpy
}

// String returns the value as a string
// Returns empty string if the data has been cleared (all zeros)
func (sv *SecureValue) String() string {
	if sv == nil || sv.data == nil {
		return ""
	}

	// Check if all data is zeros (cleared)
	allZero := true
	for _, b := range sv.data {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		return ""
	}
	return string(sv.data)
}

// Clear securely erases the value from memory
// This should be called as soon as the value is no longer needed
func (sv *SecureValue) Clear() {
	if sv != nil && sv.data != nil {
		// Overwrite memory with zeros
		for i := range sv.data {
			sv.data[i] = 0
		}
		sv.data = nil
	}
}

// SecurePassword is a wrapper for password strings that ensures memory cleanup
// This type helps prevent password data from remaining in memory after use
type SecurePassword struct {
	data []byte
}

// NewSecurePassword creates a new SecurePassword from a string
// The password string should be cleared by the caller after creating SecurePassword
func NewSecurePassword(password string) *SecurePassword {
	return &SecurePassword{
		data: []byte(password),
	}
}

// String returns the password as a string
// WARNING: The returned string will remain in memory until garbage collected
func (sp *SecurePassword) String() string {
	if sp == nil || sp.data == nil {
		return ""
	}
	return string(sp.data)
}

// Clear securely erases the password from memory
// This should be called as soon as the password is no longer needed
func (sp *SecurePassword) Clear() {
	if sp != nil && sp.data != nil {
		// Overwrite memory with zeros
		for i := range sp.data {
			sp.data[i] = 0
		}
		sp.data = nil
	}
}
