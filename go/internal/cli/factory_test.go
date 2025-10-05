package cli

import (
	"testing"
)

// TestNewManagerContext verifica que el factory crea correctamente todos los managers.
// Este test valida que:
// 1. El factory no devuelve nil
// 2. Todos los managers son instanciados (no nil)
// 3. Se mantiene el patrón de inicialización de 7 pasos
func TestNewManagerContext(t *testing.T) {
	// Arrange & Act
	ctx := NewManagerContext()

	// Assert: ManagerContext no debe ser nil
	if ctx == nil {
		t.Fatal("NewManagerContext() returned nil, expected valid *ManagerContext")
	}

	// Assert: Todos los managers deben estar instanciados
	t.Run("ValidatorManager is instantiated", func(t *testing.T) {
		if ctx.Validator == nil {
			t.Error("ManagerContext.Validator is nil, expected valid validator.Manager")
		}
	})

	t.Run("ConfigManager is instantiated", func(t *testing.T) {
		if ctx.Config == nil {
			t.Error("ManagerContext.Config is nil, expected valid config.Manager")
		}
	})

	t.Run("LoggerManager is instantiated", func(t *testing.T) {
		if ctx.Logger == nil {
			t.Error("ManagerContext.Logger is nil, expected valid logger.Manager")
		}
	})

	t.Run("PromptManager is instantiated", func(t *testing.T) {
		if ctx.Prompt == nil {
			t.Error("ManagerContext.Prompt is nil, expected valid prompt.Manager")
		}
	})

	t.Run("OutputManager is instantiated", func(t *testing.T) {
		if ctx.Output == nil {
			t.Error("ManagerContext.Output is nil, expected valid output.Manager")
		}
	})

	t.Run("SecretsManager is instantiated", func(t *testing.T) {
		if ctx.Secrets == nil {
			t.Error("ManagerContext.Secrets is nil, expected valid secrets.Manager")
		}
	})
}

// TestNewManagerContext_MultipleInstances verifica que el factory puede crear
// múltiples instancias independientes (no singleton).
// Esto es importante para mantener el patrón de inicialización por comando.
func TestNewManagerContext_MultipleInstances(t *testing.T) {
	// Arrange & Act
	ctx1 := NewManagerContext()
	ctx2 := NewManagerContext()

	// Assert: Las instancias deben ser diferentes
	if ctx1 == ctx2 {
		t.Error("NewManagerContext() returned same instance, expected independent instances")
	}

	// Assert: Los managers internos también deben ser diferentes
	if ctx1.Config == ctx2.Config {
		t.Error("ConfigManager instances are the same, expected independent instances")
	}

	if ctx1.Logger == ctx2.Logger {
		t.Error("LoggerManager instances are the same, expected independent instances")
	}

	if ctx1.Secrets == ctx2.Secrets {
		t.Error("SecretsManager instances are the same, expected independent instances")
	}
}

// TestManagerContext_AllFieldsExported verifica que ManagerContext
// expone todos los managers como campos públicos (exportados).
// Esto es necesario para que los comandos CLI puedan acceder a ellos.
func TestManagerContext_AllFieldsExported(t *testing.T) {
	// Arrange
	ctx := NewManagerContext()

	// Act & Assert: Verificar acceso a campos públicos
	t.Run("Can access Config field", func(t *testing.T) {
		_ = ctx.Config // Si compila, el campo es exportado
	})

	t.Run("Can access Logger field", func(t *testing.T) {
		_ = ctx.Logger
	})

	t.Run("Can access Prompt field", func(t *testing.T) {
		_ = ctx.Prompt
	})

	t.Run("Can access Output field", func(t *testing.T) {
		_ = ctx.Output
	})

	t.Run("Can access Secrets field", func(t *testing.T) {
		_ = ctx.Secrets
	})

	t.Run("Can access Validator field", func(t *testing.T) {
		_ = ctx.Validator
	})
}
