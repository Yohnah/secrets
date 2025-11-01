package architecture

import (
"go/ast"
"go/parser"
"go/token"
"path/filepath"
"strings"
"testing"
"io/fs"
)

// TestManagersUseInterfaces verifica que todos los managers se comunican mediante interfaces
func TestManagersUseInterfaces(t *testing.T) {
managers := []string{
"../../internal/logicmanager",
"../../internal/configmanager",
"../../internal/bdmanager",
"../../internal/outputmanager",
"../../internal/inputmanager",
}

for _, managerPath := range managers {
t.Run(filepath.Base(managerPath), func(t *testing.T) {
fset := token.NewFileSet()
pkgs, err := parser.ParseDir(fset, managerPath, func(fi fs.FileInfo) bool {
name := fi.Name()
return !strings.HasSuffix(name, "_test.go")
}, 0)

if err != nil {
t.Fatalf("Failed to parse package %s: %v", managerPath, err)
}

for _, pkg := range pkgs {
for _, file := range pkg.Files {
ast.Inspect(file, func(n ast.Node) bool {
// Verificar que structs no tienen campos de otros managers
if structType, ok := n.(*ast.StructType); ok {
for _, field := range structType.Fields.List {
if ident, ok := field.Type.(*ast.Ident); ok {
name := ident.Name
// Verificar que NO son structs concretos de otros managers
if strings.HasPrefix(name, "Standard") && name != "StandardConfig" {
t.Errorf("Manager struct should not have concrete manager field: %s", name)
}
}
}
}
return true
})
}
}
})
}
}

// TestInterfacesExist verifica que existen interfaces para cada manager principal
func TestInterfacesExist(t *testing.T) {
requiredInterfaces := map[string]string{
"../../internal/loggermanager/logger.go":     "Logger",
"../../internal/configmanager/config.go":     "Config",
"../../internal/bdmanager/bd.go":             "BD",
"../../internal/outputmanager/output.go":     "Output",
"../../internal/logicmanager/logic.go":       "LogicManager",
"../../internal/inputmanager/inputmanager.go": "InputManager",
}

for filePath, interfaceName := range requiredInterfaces {
t.Run(interfaceName, func(t *testing.T) {
fset := token.NewFileSet()
file, err := parser.ParseFile(fset, filePath, nil, 0)
if err != nil {
t.Fatalf("Failed to parse file %s: %v", filePath, err)
}

found := false
ast.Inspect(file, func(n ast.Node) bool {
if typeSpec, ok := n.(*ast.TypeSpec); ok {
if typeSpec.Name.Name == interfaceName {
if _, ok := typeSpec.Type.(*ast.InterfaceType); ok {
found = true
return false
}
}
}
return true
})

if !found {
t.Errorf("Interface %s not found in %s", interfaceName, filePath)
}
})
}
}
