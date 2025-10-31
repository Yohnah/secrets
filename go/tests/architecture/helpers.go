package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// getAllGoFiles returns all .go files in a directory recursively
func getAllGoFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// getAllGoFilesIncludingTests returns all .go files including tests
func getAllGoFilesIncludingTests(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// parseImports extracts import paths from a Go file
func parseImports(filePath string) ([]string, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}

	var imports []string
	for _, imp := range node.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		imports = append(imports, importPath)
	}
	return imports, nil
}

// parseASTFile parses a Go file and returns its AST
func parseASTFile(filePath string) (*ast.File, error) {
	fset := token.NewFileSet()
	return parser.ParseFile(fset, filePath, nil, parser.ParseComments)
}

// extractInterfaceDefinitions extracts interface definitions from an AST
func extractInterfaceDefinitions(node *ast.File) []string {
	var interfaces []string
	ast.Inspect(node, func(n ast.Node) bool {
		if typeSpec, ok := n.(*ast.TypeSpec); ok {
			if _, isInterface := typeSpec.Type.(*ast.InterfaceType); isInterface {
				interfaces = append(interfaces, typeSpec.Name.Name)
			}
		}
		return true
	})
	return interfaces
}

// extractFunctionParams extracts parameter types from function declarations
func extractFunctionParams(node *ast.File) map[string][]string {
	functions := make(map[string][]string)
	ast.Inspect(node, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			funcName := funcDecl.Name.Name
			var params []string
			if funcDecl.Type.Params != nil {
				for _, field := range funcDecl.Type.Params.List {
					params = append(params, exprToString(field.Type))
				}
			}
			functions[funcName] = params
		}
		return true
	})
	return functions
}

// exprToString converts an ast.Expr to a string representation
func exprToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprToString(t.X)
	case *ast.SelectorExpr:
		return exprToString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + exprToString(t.Elt)
	case *ast.MapType:
		return "map[" + exprToString(t.Key) + "]" + exprToString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return ""
	}
}

// isManagerDirectory checks if a directory name follows Manager naming convention
func isManagerDirectory(name string) bool {
	// Manager directories end with "manager" (lowercase)
	return strings.HasSuffix(strings.ToLower(name), "manager")
}

// isSubdomainDirectory checks if a directory name follows subdomain naming convention
func isSubdomainDirectory(name string) bool {
	// Subdomain directories are lowercase and do NOT end with "manager"
	// Examples: cli, envvars, readfile, keepassadapter, filewriter
	lower := strings.ToLower(name)

	// If name is not all lowercase, it's invalid
	if lower != name {
		return false
	}

	// If it ends with "manager", it's a Manager, not subdomain
	if strings.HasSuffix(lower, "manager") {
		return false
	}

	// It's lowercase and doesn't end with "manager" -> subdomain
	return true
}

// buildDependencyGraph builds a map of package dependencies
func buildDependencyGraph(root string) (map[string][]string, error) {
	files, err := getAllGoFiles(root)
	if err != nil {
		return nil, err
	}

	graph := make(map[string][]string)
	for _, file := range files {
		pkg := filepath.Dir(file)
		imports, err := parseImports(file)
		if err != nil {
			continue
		}

		// Filter to only internal imports
		var internalImports []string
		for _, imp := range imports {
			if strings.Contains(imp, "github.com/Yohnah/secrets/internal") {
				internalImports = append(internalImports, imp)
			}
		}

		if len(internalImports) > 0 {
			graph[pkg] = append(graph[pkg], internalImports...)
		}
	}
	return graph, nil
}

// detectCycles detects circular dependencies in a dependency graph
func detectCycles(graph map[string][]string) [][]string {
	var cycles [][]string
	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	var dfs func(string, []string) bool
	dfs = func(node string, path []string) bool {
		visited[node] = true
		recStack[node] = true
		path = append(path, node)

		for _, dep := range graph[node] {
			if !visited[dep] {
				if dfs(dep, path) {
					return true
				}
			} else if recStack[dep] {
				// Found cycle
				cycleStart := -1
				for i, p := range path {
					if p == dep {
						cycleStart = i
						break
					}
				}
				if cycleStart >= 0 {
					cycles = append(cycles, append(path[cycleStart:], dep))
				}
				return true
			}
		}

		recStack[node] = false
		return false
	}

	for node := range graph {
		if !visited[node] {
			dfs(node, []string{})
		}
	}

	return cycles
}
