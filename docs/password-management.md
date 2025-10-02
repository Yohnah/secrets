# Password Management

El CLI de secrets utiliza un sistema de gestión de contraseñas seguro que nunca almacena contraseñas en texto plano en el código.

## Métodos de Provisión de Contraseñas

### 1. Variable de Entorno (Recomendado para Automatización)
```bash
export SECRETS_YOHNAH_PASSWORD="MySecurePassword123"
secrets init
```

### 2. Entrada Interactiva (Recomendado para Uso Manual)
```bash
secrets init
# Se solicita: Enter password for KeePass database: [entrada oculta]
```

### 3. Modo Fuerza con Variable de Entorno
```bash
SECRETS_YOHNAH_PASSWORD="MySecurePassword123" secrets init --force
```

## Reglas de Seguridad

⚠️ **CRÍTICO**: 
- **NUNCA** se usan contraseñas hardcodeadas en el código
- Las contraseñas se solicitan de forma segura (sin eco en terminal)
- En modo `--force`, la contraseña DEBE estar en la variable de entorno
- Sin variable de entorno y en modo fuerza = ERROR (no se puede proceder)

## Casos de Uso

### Desarrollo Local
```bash
# Entrada interactiva (más segura)
secrets init --verbose
# Se pedirá la contraseña de forma segura
```

### CI/CD y Automatización
```bash
# Usar variable de entorno
export SECRETS_YOHNAH_PASSWORD="$KEEPASS_PASSWORD"
secrets init --force --ignore-git-repository
```

### Scripts
```bash
#!/bin/bash
if [ -z "$SECRETS_YOHNAH_PASSWORD" ]; then
    echo "Error: SECRETS_YOHNAH_PASSWORD environment variable required"
    exit 1
fi

secrets init --force
```

## Seguridad de la Base de Datos

La base de datos KeePass se protege con:
1. **Contraseña**: Proporcionada por el usuario
2. **Keyfile**: Archivo de 64 bytes generado automáticamente con permisos 600
3. **Ubicación**: `.secrets_yohnah/` con rutas configurables

## Troubleshooting

### Error: "password required but not available"
```bash
# Problema: Modo --force sin variable de entorno
secrets init --force

# Solución: Añadir variable de entorno
SECRETS_YOHNAH_PASSWORD="mypassword" secrets init --force
```

### Error: "password cannot be empty"
```bash
# Problema: Contraseña vacía en entrada interactiva
# Solución: Introducir una contraseña válida (no vacía)
```

La seguridad es primordial: todas las contraseñas se manejan de forma segura y nunca se exponen en logs o código.