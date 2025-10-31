package architecture

import (
	"path/filepath"
	"strings"
	"testing"
)

const internalPath = "../../internal"

// TestManagersUseOnlyInterfaces validates that Managers only import interfaces, not concrete implementations
func TestManagersUseOnlyInterfaces(t *testing.T) {
	files, err := getAllGoFiles(internalPath)
	if err != nil {
		t.Fatalf("Failed to get Go files: %v", err)
	}

	violations := []string{}
	for _, file := range files {
		imports, err := parseImports(file)
		if err != nil {
			t.Logf("Warning: Failed to parse imports for %s: %v", file, err)
			continue
		}

		for _, imp := range imports {
			// Check if importing internal package
			if !strings.Contains(imp, "github.com/Yohnah/secrets/internal") {
				continue
			}

			// Forbidden patterns: importing specific struct implementations
			// Allowed: importing package with interface
			// Not allowed: paths that suggest concrete implementation access
			if strings.Contains(imp, "/Standard") ||
				strings.Contains(imp, "/Cobra") ||
				strings.Contains(imp, "/Os") ||
				strings.Contains(imp, "/Stderr") {
				violations = append(violations,
					"File "+file+" imports concrete implementation: "+imp)
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("SOLID Violation (DIP): Managers must communicate via interfaces only\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestManagersCommunicateViaInterfaces validates constructor and method parameters use interfaces
func TestManagersCommunicateViaInterfaces(t *testing.T) {
	files, err := getAllGoFiles(internalPath)
	if err != nil {
		t.Fatalf("Failed to get Go files: %v", err)
	}

	violations := []string{}
	for _, file := range files {
		node, err := parseASTFile(file)
		if err != nil {
			t.Logf("Warning: Failed to parse AST for %s: %v", file, err)
			continue
		}

		functions := extractFunctionParams(node)
		for funcName, params := range functions {
			// Check constructors (New*) and public methods
			if !strings.HasPrefix(funcName, "New") && !isPublicMethod(funcName) {
				continue
			}

			for _, param := range params {
				// Check if parameter is a pointer to a struct (concrete implementation)
				if strings.HasPrefix(param, "*") && !strings.Contains(param, "interface") {
					// Allowed exceptions: basic types, standard library
					if isAllowedException(param) {
						continue
					}

					violations = append(violations,
						"Function "+funcName+" in "+filepath.Base(file)+" uses concrete type parameter: "+param)
				}
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("SOLID Violation (DIP): Functions should use interface parameters, not concrete types\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestFolderStructureCompliance validates folder structure follows conventions
func TestFolderStructureCompliance(t *testing.T) {
	entries, err := filepath.Glob(filepath.Join(internalPath, "*"))
	if err != nil {
		t.Fatalf("Failed to list internal directories: %v", err)
	}

	violations := []string{}
	for _, entry := range entries {
		info, err := filepath.Abs(entry)
		if err != nil {
			continue
		}

		baseName := filepath.Base(info)

		// Skip files, only check directories
		stat, err := filepath.Glob(entry)
		if err != nil || len(stat) == 0 {
			continue
		}

		// Check if it's a Manager (should be lowercase ending in "manager")
		if isManagerDirectory(baseName) {
			// Valid Manager directory
			// Check if at least one .go file exists in root of Manager directory
			goFiles, err := filepath.Glob(filepath.Join(entry, "*.go"))
			if err != nil || len(goFiles) == 0 {
				violations = append(violations,
					"Manager "+baseName+" missing .go files in root directory")
			}
		} else if isSubdomainDirectory(baseName) {
			// Subdomain at root level - should be inside a Manager
			violations = append(violations,
				"Subdomain "+baseName+" found at root level (should be inside a Manager)")
		}
	}

	if len(violations) > 0 {
		t.Errorf("Architecture Violation: Folder structure does not comply with conventions\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestUnitTestsColocated validates that each .go file has a corresponding _test.go
func TestUnitTestsColocated(t *testing.T) {
	files, err := getAllGoFiles(internalPath)
	if err != nil {
		t.Fatalf("Failed to get Go files: %v", err)
	}

	missing := []string{}
	for _, file := range files {
		// Skip test files themselves
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		// Generate expected test file name
		testFile := strings.TrimSuffix(file, ".go") + "_test.go"

		if !fileExists(testFile) {
			missing = append(missing, file+" is missing its test file: "+filepath.Base(testFile))
		}
	}

	if len(missing) > 0 {
		t.Errorf("Test Coverage Violation: Missing unit test files\n%s",
			strings.Join(missing, "\n"))
	}
}

// TestInterfacesInManagerRoot validates interfaces are defined in Manager root file
func TestInterfacesInManagerRoot(t *testing.T) {
	entries, err := filepath.Glob(filepath.Join(internalPath, "*"))
	if err != nil {
		t.Fatalf("Failed to list internal directories: %v", err)
	}

	violations := []string{}
	for _, entry := range entries {
		baseName := filepath.Base(entry)

		// Only check Manager directories
		if !isManagerDirectory(baseName) {
			continue
		}

		mainFile := filepath.Join(entry, baseName+".go")
		if !fileExists(mainFile) {
			continue
		}

		node, err := parseASTFile(mainFile)
		if err != nil {
			t.Logf("Warning: Failed to parse %s: %v", mainFile, err)
			continue
		}

		interfaces := extractInterfaceDefinitions(node)

		// Check if at least one interface is defined
		if len(interfaces) == 0 {
			violations = append(violations,
				"Manager "+baseName+" does not define an interface in "+baseName+".go")
		}
	}

	if len(violations) > 0 {
		t.Errorf("Architecture Violation: Managers must define interfaces in root file\n%s",
			strings.Join(violations, "\n"))
	}
}

// TestNoCircularDependencies validates no circular dependencies between packages
func TestNoCircularDependencies(t *testing.T) {
	graph, err := buildDependencyGraph(internalPath)
	if err != nil {
		t.Fatalf("Failed to build dependency graph: %v", err)
	}

	cycles := detectCycles(graph)

	if len(cycles) > 0 {
		cycleStrs := []string{}
		for _, cycle := range cycles {
			cycleStrs = append(cycleStrs, strings.Join(cycle, " -> "))
		}
		t.Errorf("Architecture Violation: Circular dependencies detected\n%s",
			strings.Join(cycleStrs, "\n"))
	}
}

// Helper functions

func isPublicMethod(name string) bool {
	if len(name) == 0 {
		return false
	}
	firstChar := rune(name[0])
	return firstChar >= 'A' && firstChar <= 'Z'
}

func isAllowedException(param string) bool {
	// Allow pointers to basic types, standard library, cobra.Command, etc.
	allowedPatterns := []string{
		"*cobra.Command",
		"*os.File",
		"*bytes.Buffer",
		"*strings.Builder",
	}

	for _, pattern := range allowedPatterns {
		if strings.Contains(param, pattern) {
			return true
		}
	}

	return false
}

func fileExists(path string) bool {
	_, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	// Actually check if file exists
	info, err := filepath.Glob(path)
	return err == nil && len(info) > 0
}
