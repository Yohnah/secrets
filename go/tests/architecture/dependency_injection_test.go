package architecture

import (
"go/ast"
"go/parser"
"go/token"
"strings"
"testing"
"io/fs"
)

// TestConstructorsUseDependencyInjection verifica que constructores reciben dependencias por parámetro
func TestConstructorsUseDependencyInjection(t *testing.T) {
managers := []struct {
path      string
constructor string
minParams int
}{
{"../../internal/configmanager/config.go", "NewStandardConfig", 3},
{"../../internal/bdmanager/bd.go", "NewStandardBD", 2},
{"../../internal/outputmanager/output.go", "NewStandardOutput", 1},
{"../../internal/logicmanager/logic.go", "NewLogicManager", 4},
}

for _, m := range managers {
t.Run(m.constructor, func(t *testing.T) {
fset := token.NewFileSet()
file, err := parser.ParseFile(fset, m.path, nil, 0)
if err != nil {
t.Fatalf("Failed to parse file %s: %v", m.path, err)
}

found := false
ast.Inspect(file, func(n ast.Node) bool {
if funcDecl, ok := n.(*ast.FuncDecl); ok {
if funcDecl.Name.Name == m.constructor {
found = true
paramCount := 0
if funcDecl.Type.Params != nil {
paramCount = funcDecl.Type.Params.NumFields()
}

if paramCount < m.minParams {
t.Errorf("%s should have at least %d parameters for dependency injection (has %d)", 
m.constructor, m.minParams, paramCount)
}
}
}
return true
})

if !found {
t.Errorf("Constructor %s not found in %s", m.constructor, m.path)
}
})
}
}

// TestNoGlobalVariables verifica que no existen variables globales mutables
func TestNoGlobalVariables(t *testing.T) {
paths := []string{
"../../internal/logicmanager",
"../../internal/configmanager",
"../../internal/bdmanager",
"../../internal/outputmanager",
}

for _, path := range paths {
t.Run(path, func(t *testing.T) {
fset := token.NewFileSet()
pkgs, err := parser.ParseDir(fset, path, func(fi fs.FileInfo) bool {
name := fi.Name()
return !strings.HasSuffix(name, "_test.go")
}, 0)

if err != nil {
t.Fatalf("Failed to parse package %s: %v", path, err)
}

for _, pkg := range pkgs {
for _, file := range pkg.Files {
for _, decl := range file.Decls {
if genDecl, ok := decl.(*ast.GenDecl); ok && genDecl.Tok == token.VAR {
for _, spec := range genDecl.Specs {
if valueSpec, ok := spec.(*ast.ValueSpec); ok {
for _, name := range valueSpec.Names {
// Permitir solo constantes y variables inmutables
if !name.IsExported() && name.Name != "Version" && name.Name != "BuildTime" && name.Name != "GitCommit" {
t.Errorf("Global mutable variable found: %s in %s", name.Name, path)
}
}
}
}
}
}
}
}
})
}
}
