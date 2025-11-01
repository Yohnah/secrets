package architecture

import (
"go/ast"
"go/parser"
"go/token"
"strings"
"testing"
"io/fs"
)

// TestManagerStructHasSingleResponsibility verifica que cada struct Standard* tiene una sola responsabilidad
func TestManagerStructHasSingleResponsibility(t *testing.T) {
managers := map[string]struct {
path          string
structName    string
maxMethods    int
maxFieldCount int
}{
"LoggerManager": {
path:          "../../internal/loggermanager/logger.go",
structName:    "StderrLogger",
maxMethods:    10,
maxFieldCount: 2,
},
"ValidatorManager": {
path:          "../../internal/validatormanager/validator.go",
structName:    "StandardValidator",
maxMethods:    10,
maxFieldCount: 2,
},
"ConfigManager": {
path:          "../../internal/configmanager/config.go",
structName:    "StandardConfig",
maxMethods:    25,
maxFieldCount: 20,
},
}

for name, m := range managers {
t.Run(name, func(t *testing.T) {
fset := token.NewFileSet()
file, err := parser.ParseFile(fset, m.path, nil, 0)
if err != nil {
t.Fatalf("Failed to parse file %s: %v", m.path, err)
}

// Count struct fields
var fieldCount int
ast.Inspect(file, func(n ast.Node) bool {
if typeSpec, ok := n.(*ast.TypeSpec); ok {
if typeSpec.Name.Name == m.structName {
if structType, ok := typeSpec.Type.(*ast.StructType); ok {
fieldCount = structType.Fields.NumFields()
}
}
}
return true
})

if fieldCount > m.maxFieldCount {
t.Errorf("%s has too many fields (%d > %d), may violate SRP", 
m.structName, fieldCount, m.maxFieldCount)
}

// Count methods
methodCount := 0
for _, decl := range file.Decls {
if funcDecl, ok := decl.(*ast.FuncDecl); ok {
if funcDecl.Recv != nil {
for _, recv := range funcDecl.Recv.List {
if starExpr, ok := recv.Type.(*ast.StarExpr); ok {
if ident, ok := starExpr.X.(*ast.Ident); ok {
if ident.Name == m.structName {
methodCount++
}
}
} else if ident, ok := recv.Type.(*ast.Ident); ok {
if ident.Name == m.structName {
methodCount++
}
}
}
}
}
}

if methodCount > m.maxMethods {
t.Logf("Warning: %s has many methods (%d), consider splitting responsibilities", 
m.structName, methodCount)
}
})
}
}

// TestPackageNaming verifica que los packages siguen la convención *manager
func TestPackageNaming(t *testing.T) {
packages := []string{
"loggermanager",
"validatormanager",
"configmanager",
"bdmanager",
"outputmanager",
"logicmanager",
"inputmanager",
}

basePath := "../../internal"

for _, pkg := range packages {
t.Run(pkg, func(t *testing.T) {
fset := token.NewFileSet()
pkgs, err := parser.ParseDir(fset, basePath+"/"+pkg, func(fi fs.FileInfo) bool {
name := fi.Name()
return !strings.HasSuffix(name, "_test.go")
}, 0)

if err != nil {
t.Fatalf("Failed to parse package %s: %v", pkg, err)
}

found := false
for pkgName := range pkgs {
if pkgName == pkg {
found = true
}
}

if !found {
t.Errorf("Package naming mismatch: expected %s", pkg)
}
})
}
}
