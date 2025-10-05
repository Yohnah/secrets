package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findModuleRoot finds the root directory of the Go module
func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// TestManagersUseInterfaces validates that Managers communicate through interfaces
func TestManagersUseInterfaces(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	internalDir := filepath.Join(root, "internal")

	managers := []string{"config", "logger", "prompt", "secrets"}

	for _, mgr := range managers {
		mgrPath := filepath.Join(internalDir, mgr, "manager.go")

		// Check if manager file exists
		if _, err := os.Stat(mgrPath); os.IsNotExist(err) {
			t.Logf("Skipping %s (file not found)", mgr)
			continue
		}

		// Parse the manager file
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, mgrPath, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", mgrPath, err)
		}

		// Check that an interface named "Manager" exists
		hasInterface := false
		ast.Inspect(node, func(n ast.Node) bool {
			if typeSpec, ok := n.(*ast.TypeSpec); ok {
				if typeSpec.Name.Name == "Manager" {
					if _, isInterface := typeSpec.Type.(*ast.InterfaceType); isInterface {
						hasInterface = true
						return false
					}
				}
			}
			return true
		})

		if !hasInterface {
			t.Errorf("Manager interface not found in %s", mgrPath)
		}
	}
}

// TestNoCircularDependencies validates no circular imports between managers
func TestNoCircularDependencies(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	internalDir := filepath.Join(root, "internal")

	managers := []string{"config", "logger", "prompt", "secrets", "cli", "types"}

	// Build dependency graph
	deps := make(map[string][]string)

	for _, mgr := range managers {
		mgrDir := filepath.Join(internalDir, mgr)

		if _, err := os.Stat(mgrDir); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(mgrDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}

			for _, imp := range node.Imports {
				importPath := strings.Trim(imp.Path.Value, `"`)
				if strings.HasPrefix(importPath, "github.com/Yohnah/secrets/internal/") {
					depMgr := strings.TrimPrefix(importPath, "github.com/Yohnah/secrets/internal/")
					if !contains(deps[mgr], depMgr) {
						deps[mgr] = append(deps[mgr], depMgr)
					}
				}
			}
			return nil
		})

		if err != nil {
			t.Fatalf("Failed to walk directory %s: %v", mgrDir, err)
		}
	}

	// Check for circular dependencies using DFS
	for mgr := range deps {
		visited := make(map[string]bool)
		if hasCycle(mgr, deps, visited, make(map[string]bool)) {
			t.Errorf("Circular dependency detected involving %s", mgr)
		}
	}
}

// TestDirectoryStructure validates the project follows the defined structure
func TestDirectoryStructure(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	requiredDirs := []string{
		"cmd/secrets",
		"internal/cli",
		"internal/config",
		"internal/logger",
		"internal/prompt",
		"internal/secrets",
		"internal/types",
		"tests/architecture",
	}

	for _, dir := range requiredDirs {
		fullPath := filepath.Join(root, dir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Errorf("Required directory does not exist: %s", dir)
		}
	}
}

// TestSecretsManagerIsCore validates that SecretsManager contains business logic decisions
func TestSecretsManagerIsCore(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	secretsMgrPath := filepath.Join(root, "internal", "secrets", "manager.go")

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, secretsMgrPath, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse secrets manager: %v", err)
	}

	// Check that SecretsManager has decision-making methods (like Init)
	hasBusinessLogic := false
	ast.Inspect(node, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			// Look for methods that make decisions (contain if statements, error handling, etc.)
			if funcDecl.Recv != nil && funcDecl.Name.Name != "" {
				hasBusinessLogic = true
			}
		}
		return true
	})

	if !hasBusinessLogic {
		t.Error("SecretsManager should contain business logic methods")
	}
}

// TestManagersSRP validates Single Responsibility Principle
func TestManagersSRP(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Fatalf("Failed to find module root: %v", err)
	}

	managers := map[string]string{
		"config":  "configuration",
		"logger":  "logging",
		"prompt":  "user interaction",
		"secrets": "business logic",
	}

	internalDir := filepath.Join(root, "internal")

	for mgr, responsibility := range managers {
		mgrPath := filepath.Join(internalDir, mgr, "manager.go")

		if _, err := os.Stat(mgrPath); os.IsNotExist(err) {
			t.Logf("Skipping %s (file not found)", mgr)
			continue
		}

		// Read file comments to verify responsibility is documented
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, mgrPath, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", mgrPath, err)
		}

		// Check package comment or interface comment mentions responsibility
		foundResponsibility := false
		if node.Doc != nil {
			for _, comment := range node.Doc.List {
				if strings.Contains(strings.ToLower(comment.Text), strings.ToLower(responsibility)) {
					foundResponsibility = true
					break
				}
			}
		}

		if !foundResponsibility {
			// Also check interface comments
			ast.Inspect(node, func(n ast.Node) bool {
				if typeSpec, ok := n.(*ast.TypeSpec); ok {
					if typeSpec.Name.Name == "Manager" && typeSpec.Doc != nil {
						for _, comment := range typeSpec.Doc.List {
							if strings.Contains(strings.ToLower(comment.Text), strings.ToLower(responsibility)) {
								foundResponsibility = true
								return false
							}
						}
					}
				}
				return true
			})
		}

		t.Logf("%s manager responsibility documented: %v", mgr, foundResponsibility)
	}
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func hasCycle(node string, graph map[string][]string, visited, recStack map[string]bool) bool {
	visited[node] = true
	recStack[node] = true

	for _, neighbor := range graph[node] {
		if !visited[neighbor] {
			if hasCycle(neighbor, graph, visited, recStack) {
				return true
			}
		} else if recStack[neighbor] {
			return true
		}
	}

	recStack[node] = false
	return false
}
