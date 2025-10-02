# Semantic Versioning System

El CLI de secrets utiliza un sistema de versionado semántico avanzado que proporciona información detallada sobre la versión, el estado del código y el entorno de compilación.

## Formato de Versiones

### Versiones de Release (con tags semánticos)
```bash
# Tag limpio (sin cambios)
$ secrets --version
secrets version v1.2.3
  commit: abc1234
  built: 2025-10-01T18:30:20Z
  go: go1.24.7

# Tag con cambios locales
$ secrets --version  
secrets version v1.2.3-dirty
  commit: abc1234
  built: 2025-10-01T18:30:20Z
  go: go1.24.7
```

### Versiones de Desarrollo (sin tags semánticos)
```bash
# Commit de desarrollo limpio
$ secrets --version
secrets version v0.1.0-dev+20251001.abc1234
  commit: abc1234
  built: 2025-10-01T18:31:06Z
  go: go1.24.7

# Commit de desarrollo con cambios locales
$ secrets --version
secrets version v0.1.0-dev+20251001.abc1234-dirty
  commit: abc1234
  built: 2025-10-01T18:31:06Z
  go: go1.24.7
```

## Reglas de Versionado

1. **Tags Semánticos**: Solo se consideran tags que sigan el patrón `v[0-9]+\.[0-9]+\.[0-9]+` (ej: v1.0.0, v2.1.3)
2. **Tags No Semánticos**: Se ignoran tags como "hito-funcional", "release-candidate", etc.
3. **Estado Dirty**: Se detecta automáticamente cuando hay cambios no confirmados
4. **Versión Base**: v0.1.0 para desarrollo cuando no hay tags semánticos

## Información Detallada

La salida del comando `--version` incluye:
- **Version**: Versión semántica o de desarrollo
- **Commit**: Hash corto del commit actual
- **Built**: Timestamp ISO8601 de cuando se compiló el binario
- **Go**: Versión del compilador Go utilizada

## Creación de Releases

Para crear una nueva versión de release:

```bash
# Crear tag semántico
git tag v1.2.3

# Compilar con la versión
make build

# Verificar la versión
./bin/secrets --version
```

El sistema es completamente automático y no requiere modificación manual de archivos de versión.