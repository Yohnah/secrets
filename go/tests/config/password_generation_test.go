package config

import (
	"testing"

	"github.com/Yohnah/secrets/internal/config"
	"github.com/Yohnah/secrets/internal/types"
	"github.com/Yohnah/secrets/internal/validator"
)

func TestGenerateSecurePassword_Uniqueness(t *testing.T) {
	mgr := config.NewManager(&types.GlobalFlags{}, &types.CommandFlags{}, validator.NewManager())

	passwords := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		pwd := mgr.GenerateSecurePassword()
		if passwords[pwd] {
			t.Errorf("Generated duplicate password: %s", pwd)
		}
		passwords[pwd] = true
	}

	if len(passwords) != iterations {
		t.Errorf("Expected %d unique passwords, got %d", iterations, len(passwords))
	}
}

func TestGenerateSecurePassword_MeetsComplexity(t *testing.T) {
	mgr := config.NewManager(&types.GlobalFlags{}, &types.CommandFlags{}, validator.NewManager())

	passesCount := 0
	iterations := 100

	for i := 0; i < iterations; i++ {
		pwd := mgr.GenerateSecurePassword()

		if len(pwd) < 8 {
			t.Errorf("Password too short: %d chars", len(pwd))
		}

		var hasLower, hasUpper, hasDigit, hasSpecial bool
		for _, char := range pwd {
			if char >= 'a' && char <= 'z' {
				hasLower = true
			} else if char >= 'A' && char <= 'Z' {
				hasUpper = true
			} else if char >= '0' && char <= '9' {
				hasDigit = true
			} else {
				hasSpecial = true
			}
		}

		if hasLower && hasUpper && hasDigit && hasSpecial {
			passesCount++
		}
	}

	expectedPasses := int(float64(iterations) * 0.6)
	if passesCount < expectedPasses {
		t.Errorf("Expected at least %d passwords to meet complexity, got %d", expectedPasses, passesCount)
	}
}

func TestGenerateSecurePassword_Length(t *testing.T) {
	mgr := config.NewManager(&types.GlobalFlags{}, &types.CommandFlags{}, validator.NewManager())

	for i := 0; i < 10; i++ {
		pwd := mgr.GenerateSecurePassword()
		if len(pwd) != 16 {
			t.Errorf("Expected password length 16, got %d", len(pwd))
		}
	}
}
