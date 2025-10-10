package secrets_test

import (
	"testing"

	"github.com/Yohnah/secrets/internal/secrets/common"
)

func TestSecureValue_NewSecureValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty string", ""},
		{"simple string", "test"},
		{"password with special chars", "P@ssw0rd!123"},
		{"unicode string", "пароль"},
		{"long string", "This is a very long password that should be handled correctly by the SecureValue implementation and not cause any issues with memory management or string operations. It contains various characters including spaces and punctuation!@#$%^&*()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := common.NewSecureValue(tt.value)
			if sv == nil {
				t.Fatal("NewSecureValue returned nil")
			}

			// Verify String() returns correct value
			if sv.String() != tt.value {
				t.Errorf("String() = %q, want %q", sv.String(), tt.value)
			}

			// Clean up
			sv.Clear()
		})
	}
}

func TestSecureValue_Clear(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty string", ""},
		{"simple string", "test"},
		{"password", "secret123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := common.NewSecureValue(tt.value)

			// Verify value is accessible before clear
			if sv.String() != tt.value {
				t.Errorf("Before Clear(): String() = %q, want %q", sv.String(), tt.value)
			}

			// Clear the value
			sv.Clear()

			// Verify value is zeroed out
			if sv.String() != "" {
				t.Errorf("After Clear(): String() = %q, want empty string", sv.String())
			}

			// Verify underlying bytes are zeroed
			bytes := sv.Bytes()
			for i, b := range bytes {
				if b != 0 {
					t.Errorf("Byte at index %d is %d, expected 0", i, b)
				}
			}
		})
	}
}

func TestSecureValue_Bytes(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty string", ""},
		{"ASCII string", "hello"},
		{"binary data", string([]byte{0, 1, 2, 255})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := common.NewSecureValue(tt.value)
			defer sv.Clear()

			bytes := sv.Bytes()

			// Verify bytes match original value
			if string(bytes) != tt.value {
				t.Errorf("Bytes() = %q, want %q", string(bytes), tt.value)
			}

			// Verify length
			if len(bytes) != len(tt.value) {
				t.Errorf("Bytes() length = %d, want %d", len(bytes), len(tt.value))
			}
		})
	}
}

func TestSecureValue_MemorySafety(t *testing.T) {
	originalValue := "sensitive_data_123"
	sv := common.NewSecureValue(originalValue)

	// Verify data is accessible initially
	if sv.String() != originalValue {
		t.Errorf("Initial String() = %q, want %q", sv.String(), originalValue)
	}

	// Clear and verify data is zeroed
	sv.Clear()

	// Check that String() returns empty after clear
	if sv.String() != "" {
		t.Errorf("After Clear(): String() = %q, expected empty", sv.String())
	}

	// Check that Bytes() returns nil or empty slice after clear
	bytes := sv.Bytes()
	if bytes != nil && len(bytes) != 0 {
		t.Errorf("After Clear(): Bytes() should return nil or empty, got length %d", len(bytes))
	}
}

func TestSecureValue_MultipleOperations(t *testing.T) {
	sv := common.NewSecureValue("initial")

	// Multiple String() calls should work
	for i := 0; i < 5; i++ {
		if sv.String() != "initial" {
			t.Errorf("String() call %d = %q, want %q", i, sv.String(), "initial")
		}
	}

	// Multiple Bytes() calls should work
	for i := 0; i < 3; i++ {
		bytes := sv.Bytes()
		if string(bytes) != "initial" {
			t.Errorf("Bytes() call %d = %q, want %q", i, string(bytes), "initial")
		}
	}

	// Clear should work
	sv.Clear()
	if sv.String() != "" {
		t.Errorf("After Clear(): String() = %q, want empty", sv.String())
	}
}

func TestSecurePassword_NewSecurePassword(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty password", ""},
		{"simple password", "password123"},
		{"complex password", "P@ssw0rd!#$%^&*()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sp := common.NewSecurePassword(tt.value)
			if sp == nil {
				t.Fatal("NewSecurePassword returned nil")
			}

			// Verify String() returns correct value
			if sp.String() != tt.value {
				t.Errorf("String() = %q, want %q", sp.String(), tt.value)
			}

			// Clean up
			sp.Clear()
		})
	}
}

func TestSecurePassword_Clear(t *testing.T) {
	sp := common.NewSecurePassword("secret_password")

	// Verify value before clear
	if sp.String() != "secret_password" {
		t.Errorf("Before Clear(): String() = %q", sp.String())
	}

	// Clear
	sp.Clear()

	// Verify cleared
	if sp.String() != "" {
		t.Errorf("After Clear(): String() = %q, want empty", sp.String())
	}
}

func TestGetPassword(t *testing.T) {
	// This test requires mocking the prompt manager
	// Since GetPassword uses dependency injection, we'll test the logic indirectly
	// through integration tests that use the actual services

	t.Run("interface compliance", func(t *testing.T) {
		// Verify that PromptManagerInterface is properly defined
		var _ common.PromptManagerInterface = (*mockPromptManager)(nil)
	})
}

// mockPromptManager for testing
type mockPromptManager struct {
	passwordToReturn string
	errorToReturn    error
}

func (m *mockPromptManager) PromptPassword(message string) (*common.SecureValue, error) {
	if m.errorToReturn != nil {
		return nil, m.errorToReturn
	}
	return common.NewSecureValue(m.passwordToReturn), nil
}

func (m *mockPromptManager) PromptPasswordConfirm(message string) (*common.SecureValue, error) {
	if m.errorToReturn != nil {
		return nil, m.errorToReturn
	}
	return common.NewSecureValue(m.passwordToReturn), nil
}
