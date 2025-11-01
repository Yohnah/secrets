package validatormanager

import (
"fmt"
"regexp"
"github.com/Yohnah/secrets/internal/loggermanager"
)

type Validator interface {
ValidateDatabaseName(name string) error
ValidatePath(path string) error
ValidatePassword(password string) error
}

type StandardValidator struct {
logger loggermanager.Logger
}

func NewStandardValidator(logger loggermanager.Logger) Validator {
return &StandardValidator{logger: logger}
}

func (v *StandardValidator) ValidateDatabaseName(name string) error {
if name == "" {
return fmt.Errorf("database name cannot be empty")
}
if len(name) > 64 {
return fmt.Errorf("database name too long")
}
match, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
if !match {
return fmt.Errorf("database name must be alphanumeric")
}
return nil
}

func (v *StandardValidator) ValidatePath(path string) error {
if path == "" {
return fmt.Errorf("path cannot be empty")
}
return nil
}

func (v *StandardValidator) ValidatePassword(password string) error {
if password == "" {
return fmt.Errorf("password cannot be empty")
}
return nil
}
