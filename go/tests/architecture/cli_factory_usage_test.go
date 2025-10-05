package architecture

import (
"go/ast"
"go/parser"
"go/token"
"os"
"path/filepath"
"strings"
"testing"
)

// TestCLICommandsUseFactory verifies that all CLI commands use the factory
// NewManagerContext() instead of duplicating manager initialization code.
//
// This architecture test ensures that:
// 1. All CLI command files call NewManagerContext()
// 2. There is no duplicated manager initialization code
// 3. The centralized factory pattern is maintained
//
// Commands excluded from analysis:
// - root.go: Defines the root command and global flags
// - factory.go: Is the factory itself
// - factory_test.go: Tests for the factory
//
// Architecture directive: After refactoring with factory pattern,
// ALL CLI commands MUST use NewManagerContext() to obtain their managers.
// This eliminates duplication and centralizes the 7-step initialization pattern.
func TestCLICommandsUseFactory(t *testing.T) {
// Arrange: CLI commands directory
cliDir := "/workspaces/secrets/go/internal/cli"

// Act: Read all .go files in the CLI directory
files, err := os.ReadDir(cliDir)
if err != nil {
t.Fatalf("Failed to read CLI directory: %v", err)
}

// Files that are NOT CLI commands (excluded from analysis)
excludedFiles := map[string]bool{
"root.go":         true, // Defines rootCmd and global flags
"factory.go":      true, // Is the factory itself
"factory_test.go": true, // Tests for the factory
}

// Counters for report
commandsFound := 0
commandsUsingFactory := 0
var commandsNotUsingFactory []string

// Assert: Verify each command file
for _, file := range files {
filename := file.Name()

// Ignore directories, tests and excluded files
if file.IsDir() || !strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, "_test.go") {
continue
}

if excludedFiles[filename] {
continue
}

// Parse the file
filePath := filepath.Join(cliDir, filename)
usesFactory, err := fileUsesFactory(filePath)
if err != nil {
t.Errorf("Failed to analyze %s: %v", filename, err)
continue
}

commandsFound++
if usesFactory {
commandsUsingFactory++
t.Logf("✓ %s uses NewManagerContext()", filename)
} else {
commandsNotUsingFactory = append(commandsNotUsingFactory, filename)
t.Errorf("✗ %s does NOT use NewManagerContext() - duplicates initialization code", filename)
}
}

// Verify that commands were found
if commandsFound == 0 {
t.Fatal("No CLI command files found - test configuration error")
}

// Final report
t.Logf("\n=== CLI Factory Usage Report ===")
t.Logf("Commands analyzed: %d", commandsFound)
t.Logf("Commands using factory: %d", commandsUsingFactory)
t.Logf("Commands with duplicated code: %d", len(commandsNotUsingFactory))

if len(commandsNotUsingFactory) > 0 {
t.Logf("\nCommands NOT using factory pattern:")
for _, cmd := range commandsNotUsingFactory {
t.Logf("  - %s", cmd)
}
t.Errorf("\nArchitecture violation: %d command(s) duplicate manager initialization instead of using NewManagerContext()", len(commandsNotUsingFactory))
}
}

// fileUsesFactory analyzes a Go file and determines if it uses NewManagerContext().
// Returns true if the file contains a call to NewManagerContext().
func fileUsesFactory(filePath string) (bool, error) {
// Parse the Go file
fset := token.NewFileSet()
node, err := parser.ParseFile(fset, filePath, nil, parser.AllErrors)
if err != nil {
return false, err
}

// Search for calls to NewManagerContext()
usesFactory := false
ast.Inspect(node, func(n ast.Node) bool {
// Look for call expressions (CallExpr)
call, ok := n.(*ast.CallExpr)
if !ok {
return true
}

// Check if it's a call to NewManagerContext
if ident, ok := call.Fun.(*ast.Ident); ok {
if ident.Name == "NewManagerContext" {
usesFactory = true
return false // Found, no need to continue searching
}
}

return true
})

return usesFactory, nil
}

// TestCLICommandsNoDuplicatedInitialization verifies that CLI commands
// do NOT duplicate manager initialization code.
//
// This test looks for code patterns that indicate manual initialization:
// - validator.NewManager()
// - config.NewManager()
// - logger.NewManager()
// - secrets.NewManager()
//
// If a command contains these patterns, it means it's duplicating
// logic that should be centralized in the factory.
//
// Excluded files:
// - factory.go: Contains the legitimate implementation
// - Tests: Can instantiate managers for unit tests
func TestCLICommandsNoDuplicatedInitialization(t *testing.T) {
// Arrange: CLI commands directory
cliDir := "/workspaces/secrets/go/internal/cli"

// Patterns that indicate manual initialization (duplication)
duplicationPatterns := []string{
"validator.NewManager()",
"config.NewManager(",
"logger.NewManager(",
"secrets.NewManager(",
"prompt.NewManager()",
"output.NewManager()",
}

// Files that CAN contain these patterns (not violations)
allowedFiles := map[string]bool{
"factory.go":      true, // Legitimate factory implementation
"factory_test.go": true, // Tests can instantiate managers
}

// Act: Read all .go files
files, err := os.ReadDir(cliDir)
if err != nil {
t.Fatalf("Failed to read CLI directory: %v", err)
}

violationsFound := false

// Assert: Verify each file
for _, file := range files {
filename := file.Name()

// Ignore directories, tests and allowed files
if file.IsDir() || !strings.HasSuffix(filename, ".go") {
continue
}

if allowedFiles[filename] || strings.HasSuffix(filename, "_test.go") {
continue
}

// Read file content
filePath := filepath.Join(cliDir, filename)
content, err := os.ReadFile(filePath)
if err != nil {
t.Errorf("Failed to read %s: %v", filename, err)
continue
}

fileContent := string(content)

// Search for duplication patterns
for _, pattern := range duplicationPatterns {
if strings.Contains(fileContent, pattern) {
t.Errorf("✗ %s contains duplicated initialization code: %s", filename, pattern)
violationsFound = true
}
}
}

if !violationsFound {
t.Log("✓ No duplicated manager initialization found in CLI commands")
}
}

// TestFactoryFileExists verifies that the factory.go file exists and is accessible.
// This test ensures that the factory is available for all commands.
func TestFactoryFileExists(t *testing.T) {
// Arrange
factoryPath := "/workspaces/secrets/go/internal/cli/factory.go"

// Act
info, err := os.Stat(factoryPath)

// Assert
if err != nil {
if os.IsNotExist(err) {
t.Fatalf("factory.go does not exist at %s", factoryPath)
}
t.Fatalf("Failed to check factory.go: %v", err)
}

if info.IsDir() {
t.Fatalf("factory.go is a directory, expected a file")
}

if info.Size() == 0 {
t.Error("factory.go is empty")
}

t.Logf("✓ factory.go exists and is accessible (%d bytes)", info.Size())
}
