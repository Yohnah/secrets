package cli

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"github.com/Yohnah/secrets/internal/keepass"
)

// Statistical output functions (no verbose logging)
func outputJSON(data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		logError("Error serializing JSON", err)
		return
	}
	fmt.Println(string(jsonData))
}

func logStats(operation string, duration time.Duration, status string) {
	stats := map[string]interface{}{
		"operation": operation,
		"duration":  duration.String(),
		"status":    status,
		"timestamp": time.Now().Format("2006-01-02 15:04:05"),
	}
	outputJSON(stats)
}

func logSuccess(message string) {
	fmt.Printf("SUCCESS: %s\n", message)
}

func logError(message string, err error) {
	fmt.Printf("ERROR: %s: %v\n", message, err)
	os.Exit(1)
}

func logInfo(message string) {
	fmt.Printf("INFO: %s\n", message)
}

// Interactive prompt utilities
// promptInput prompts for string input with optional default value
func promptInput(message string, defaultValue string, force bool) (string, error) {
	if force {
		if defaultValue == "" {
			return "", fmt.Errorf("no default value provided for prompt: %s", message)
		}
		return defaultValue, nil
	}
	
	if defaultValue != "" {
		fmt.Printf("%s [default: %s]: ", message, defaultValue)
	} else {
		fmt.Printf("%s: ", message)
	}
	
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("error reading input: %v", err)
	}
	
	input = strings.TrimSpace(input)
	if input == "" && defaultValue != "" {
		return defaultValue, nil
	}
	
	return input, nil
}

// promptConfirm prompts for yes/no confirmation with optional default value
func promptConfirm(message string, defaultValue bool, force bool) (bool, error) {
	if force {
		return defaultValue, nil
	}
	
	defaultStr := "no"
	if defaultValue {
		defaultStr = "yes"
	}
	
	fmt.Printf("%s (yes/no) [default: %s]: ", message, defaultStr)
	
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("error reading input: %v", err)
	}
	
	input = strings.TrimSpace(strings.ToLower(input))
	
	if input == "" {
		return defaultValue, nil
	}
	
	switch input {
	case "y", "yes", "true", "1":
		return true, nil
	case "n", "no", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid input: %s (expected yes/no)", input)
	}
}

// findGitRoot finds the root directory of the current git repository
func findGitRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository or git not available: %v", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// createSecretsDirectory creates .secrets_yohnah directory in git root
func createSecretsDirectory(gitRoot string, verbose bool) error {
	secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
	
	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(secretsDir, 0755); err != nil {
			return fmt.Errorf("failed to create secrets directory: %v", err)
		}
		if verbose {
			logSuccess(fmt.Sprintf("Created secrets directory: %s", secretsDir))
		}
	} else {
		if verbose {
			logInfo(fmt.Sprintf("Secrets directory already exists: %s", secretsDir))
		}
	}
	
	return nil
}

// ensureGitignoreEntry ensures .secrets_yohnah is in .gitignore
func ensureGitignoreEntry(gitRoot string, verbose bool) error {
	gitignorePath := filepath.Join(gitRoot, ".gitignore")
	secretsEntry := ".secrets_yohnah"
	
	// Read existing .gitignore if it exists
	var lines []string
	var found bool
	var fileExists bool
	
	if file, err := os.Open(gitignorePath); err == nil {
		fileExists = true
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			lines = append(lines, scanner.Text())
			if line == secretsEntry {
				found = true
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading .gitignore: %v", err)
		}
	} else if !os.IsNotExist(err) {
		// If error is not "file doesn't exist", return the error
		return fmt.Errorf("error accessing .gitignore: %v", err)
	}
	
	// Add entry if not found
	if !found {
		// Add newline before entry if file exists and doesn't end with newline
		if len(lines) > 0 && lines[len(lines)-1] != "" {
			lines = append(lines, "")
		}
		
		// Add comment and entry
		lines = append(lines, "# Secrets directory - never commit")
		lines = append(lines, secretsEntry)
		
		// Write back to file (creates file if it doesn't exist)
		file, err := os.Create(gitignorePath)
		if err != nil {
			return fmt.Errorf("error creating .gitignore: %v", err)
		}
		defer file.Close()
		
		for _, line := range lines {
			if _, err := file.WriteString(line + "\n"); err != nil {
				return fmt.Errorf("error writing to .gitignore: %v", err)
			}
		}
		
		if verbose {
			if fileExists {
				logSuccess(fmt.Sprintf("Added .secrets_yohnah to existing .gitignore: %s", gitignorePath))
			} else {
				logSuccess(fmt.Sprintf("Created .gitignore with .secrets_yohnah entry: %s", gitignorePath))
			}
		}
	} else {
		if verbose {
			logInfo(fmt.Sprintf(".secrets_yohnah already in .gitignore: %s", gitignorePath))
		}
	}
	
	return nil
}

// createConfigFile creates config.yml in .secrets_yohnah directory if it doesn't exist
func createConfigFile(gitRoot string, verbose bool) error {
	secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
	configPath := filepath.Join(secretsDir, "config.yml")
	
	// Check if config.yml already exists
	if _, err := os.Stat(configPath); err == nil {
		if verbose {
			logInfo(fmt.Sprintf("Config file already exists: %s", configPath))
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking config file: %v", err)
	}
	
	// Create config.yml with paths based on default flag values
	configContent := fmt.Sprintf(`# Configuration file for secrets management
# Paths are relative to the .secrets_yohnah directory

# KeePass database configuration
database_path: "./secrets.kdbx"
database_key: "./secrets.key"
`)
	
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("error creating config file: %v", err)
	}
	
	if verbose {
		logSuccess(fmt.Sprintf("Created config file: %s", configPath))
	}
	
	return nil
}

// NewInitCommand creates the init command
func NewInitCommand(app *CLIApp) *cobra.Command {
	var noCreateDatabase bool
	
	cmd := &cobra.Command{
		Use:   "init [yaml-file]",
		Short: "Initialize configuration from YAML file (defaults to secrets.yml in git root)",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			start := time.Now()
			
			// Determine the YAML file to use
			var yamlFile string
			if len(args) > 0 {
				yamlFile = args[0]
			} else {
				// Find git root and look for secrets.yml
				gitRoot, err := findGitRoot()
				if err != nil {
					logError("Could not find git repository root", err)
					return
				}
				yamlFile = filepath.Join(gitRoot, "secrets.yml")
				
				// Check if the default file exists
				if _, err := os.Stat(yamlFile); os.IsNotExist(err) {
					logError("Default secrets.yml not found", fmt.Errorf("file not found: %s", yamlFile))
					logInfo("Please create a secrets.yml file in the git root or specify a custom path:")
					logInfo("  secrets init /path/to/your/file.yml")
					return
				}
			}
			
			verbose := app.IsVerbose()
			force := app.IsForce()
			
			if verbose {
				logInfo(fmt.Sprintf("Using configuration file: %s", yamlFile))
			}
			
			// Check if using external database/keyfile paths
			usingExternalPaths := app.UsingExternalPaths()
			
			var dbPath, keyfilePath string
			
			if usingExternalPaths {
				// Use paths from flags, skip .secrets_yohnah creation
				dbPath = app.GetDatabase()
				keyfilePath = app.GetKeyfile()
				
				if verbose {
					if dbPath != "" {
						logInfo(fmt.Sprintf("Using external database: %s", dbPath))
					}
					if keyfilePath != "" {
						logInfo(fmt.Sprintf("Using external keyfile: %s", keyfilePath))
					}
				}
			} else {
				// Standard workflow with .secrets_yohnah
				
				// Find git root
				gitRoot, err := findGitRoot()
				if err != nil {
					logError("Failed to find git repository root", err)
					return
				}
				
				if verbose {
					logInfo(fmt.Sprintf("Git repository root: %s", gitRoot))
				}
				
				// Create .secrets_yohnah directory
				if err := createSecretsDirectory(gitRoot, verbose); err != nil {
					logError("Failed to create secrets directory", err)
					return
				}
				
				// Ensure .secrets_yohnah is in .gitignore
				if err := ensureGitignoreEntry(gitRoot, verbose); err != nil {
					logError("Failed to update .gitignore", err)
					return
				}
				
				// Create config.yml in .secrets_yohnah directory
				if err := createConfigFile(gitRoot, verbose); err != nil {
					logError("Failed to create config file", err)
					return
				}
				
				// Read config to get database and keyfile paths
				configPath := filepath.Join(gitRoot, ".secrets_yohnah", "config.yml")
				config, err := readConfigFile(configPath)
				if err != nil {
					logError("Failed to read config file", err)
					return
				}
				
				// Get paths from config
				dbRelativePath := config["database_path"]
				keyfileRelativePath := config["database_key"]
				
				if dbRelativePath == "" || keyfileRelativePath == "" {
					logError("Invalid config file: missing database_path or database_key", fmt.Errorf("config validation failed"))
					return
				}
				
				secretsDir := filepath.Join(gitRoot, ".secrets_yohnah")
				dbPath = filepath.Join(secretsDir, dbRelativePath[2:]) // Remove "./" prefix
				keyfilePath = filepath.Join(secretsDir, keyfileRelativePath[2:]) // Remove "./" prefix
			}
			
			// Check if database exists and handle creation
			if !noCreateDatabase {
				if _, err := os.Stat(dbPath); os.IsNotExist(err) {
					// Database doesn't exist, ask if should create
					shouldCreate, err := promptConfirm("Create KeePass database", true, force)
					if err != nil {
						logError("Failed to get user confirmation", err)
						return
					}
					
					if shouldCreate {
						// Get password (always interactive, even with force)
						password, err := promptPassword("Enter password for KeePass database")
						if err != nil {
							logError("Failed to get password", err)
							return
						}
						
						if password == "" {
							logError("Password cannot be empty", fmt.Errorf("empty password"))
							return
						}
						
						// Create database and keyfile
						if err := createKeePassDatabase(dbPath, keyfilePath, password, verbose); err != nil {
							logError("Failed to create KeePass database", err)
							return
						}
						
						if verbose {
							logSuccess("KeePass database and keyfile created successfully")
						}
					}
				} else {
					// Database already exists - update groups based on current YAML
					if verbose {
						logInfo(fmt.Sprintf("KeePass database already exists: %s", dbPath))
					}
					
					// Update groups from current YAML file
					if err := updateKeePassGroupsFromYaml(dbPath, keyfilePath, yamlFile, verbose); err != nil {
						logError("Failed to update KeePass groups from YAML", err)
						return
					}
				}
			} else if verbose {
				logInfo("Database creation skipped due to --no-create-database flag")
			}
			
			// Verify YAML file exists
			if _, err := os.Stat(yamlFile); os.IsNotExist(err) {
				logError(fmt.Sprintf("YAML file does not exist: %s", yamlFile), err)
				return
			}
			
			if verbose {
				logSuccess(fmt.Sprintf("Successfully processed init command for: %s", yamlFile))
				logStats("init", time.Since(start), "success")
			}
		},
	}
	
	// Add command-specific flag
	cmd.Flags().BoolVar(&noCreateDatabase, "no-create-database", false, "do not create KeePass database if it doesn't exist")
	
	return cmd
}

// promptPassword prompts for password input (always interactive, no force bypass)
func promptPassword(message string) (string, error) {
	fmt.Printf("%s: ", message)
	
	// Read password without echoing
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("error reading password: %v", err)
	}
	
	fmt.Println() // Print newline after password input
	return string(bytePassword), nil
}

// generateKeyfile creates a random keyfile
func generateKeyfile(keyfilePath string) error {
	// Generate 256 bytes of random data
	keyData := make([]byte, 256)
	if _, err := rand.Read(keyData); err != nil {
		return fmt.Errorf("failed to generate random key: %v", err)
	}
	
	// Write keyfile
	if err := os.WriteFile(keyfilePath, keyData, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile: %v", err)
	}
	
	return nil
}

// createKeePassDatabase creates a new KeePass database with keyfile and password
func createKeePassDatabase(dbPath, keyfilePath, password string, verbose bool) error {
	// First create the keyfile in the specified path
	if err := generateKeyfile(keyfilePath); err != nil {
		return fmt.Errorf("failed to create keyfile: %v", err)
	}
	
	if verbose {
		logSuccess(fmt.Sprintf("Created keyfile: %s", keyfilePath))
	}

	// Read the profile from secrets.yaml to create the base group
	profile, err := readProfileFromSecretsYaml()
	if err != nil {
		return fmt.Errorf("failed to read profile from secrets.yaml: %v", err)
	}

	// Create actual KeePass database using the existing keyfile
	if err := createKeePassDatabaseWithProfile(dbPath, keyfilePath, password, profile, verbose); err != nil {
		return fmt.Errorf("failed to create KeePass database: %v", err)
	}

	if verbose {
		logSuccess(fmt.Sprintf("Created KeePass database: %s", dbPath))
		if profile != "" {
			logSuccess(fmt.Sprintf("Created base group: /%s/", profile))
		}
	}

	return nil
}

// readConfigFile reads and parses the config.yml file
func readConfigFile(configPath string) (map[string]string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	
	config := make(map[string]string)
	lines := strings.Split(string(content), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes if present
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
				value = value[1 : len(value)-1]
			}
			config[key] = value
		}
	}
	
	return config, nil
}

// readProfileFromSecretsYaml reads the profile from secrets.yaml metadata section
func readProfileFromSecretsYaml() (string, error) {
	secretsYamlPath := "secrets.yaml"
	
	// Check if secrets.yaml exists
	if _, err := os.Stat(secretsYamlPath); os.IsNotExist(err) {
		// If secrets.yaml doesn't exist, return empty profile (no base group)
		return "", nil
	}
	
	content, err := os.ReadFile(secretsYamlPath)
	if err != nil {
		return "", fmt.Errorf("error reading secrets.yaml: %v", err)
	}
	
	// Split by YAML document separator
	documents := strings.Split(string(content), "---")
	if len(documents) == 0 {
		return "", nil
	}
	
	// Parse the first document (metadata)
	metadataDoc := strings.TrimSpace(documents[0])
	lines := strings.Split(metadataDoc, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "profile:") {
			// Extract profile value
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				profile := strings.TrimSpace(parts[1])
				// Remove quotes if present
				if strings.HasPrefix(profile, "\"") && strings.HasSuffix(profile, "\"") {
					profile = profile[1 : len(profile)-1]
				}
				return profile, nil
			}
		}
	}
	
	return "", nil
}

// createKeePassDatabaseWithProfile creates a KeePass database with base group
func createKeePassDatabaseWithProfile(dbPath, keyfilePath, password, profile string, verbose bool) error {
	// Create a new KeePass instance
	kp, err := keepass.New(dbPath)
	if err != nil {
		return fmt.Errorf("error creating KeePass instance: %v", err)
	}
	
	// Read the existing keyfile data
	keyData, err := os.ReadFile(keyfilePath)
	if err != nil {
		return fmt.Errorf("error reading keyfile %s: %v", keyfilePath, err)
	}
	
	// Create the database with external keyfile data
	if err := kp.CreateDBWithKeyData("admin", password, keyData); err != nil {
		return fmt.Errorf("error creating KeePass database: %v", err)
	}
	
	// Create the base group if profile is specified
	if profile != "" {
		// Create the profile group directly (no entries needed)
		if err := kp.CreateGroup(profile); err != nil {
			return fmt.Errorf("error creating base group %s: %v", profile, err)
		}
		
		if verbose {
			logInfo(fmt.Sprintf("Created base group: /%s/", profile))
		}
	}
	
	// Save the database
	if err := kp.Save(); err != nil {
		return fmt.Errorf("error saving KeePass database: %v", err)
	}
	
	return nil
}

// updateKeePassGroupsFromYaml updates KeePass groups based on current YAML file
func updateKeePassGroupsFromYaml(dbPath, keyfilePath, yamlFile string, verbose bool) error {
	// Read profile from the specified YAML file
	profile, err := readProfileFromSpecificYaml(yamlFile)
	if err != nil {
		return fmt.Errorf("error reading profile from YAML file %s: %v", yamlFile, err)
	}
	
	// If no profile specified, nothing to update
	if profile == "" {
		if verbose {
			logInfo("No profile specified in YAML metadata, skipping group updates")
		}
		return nil
	}
	
	// Open existing KeePass database
	kp, err := keepass.New(dbPath)
	if err != nil {
		return fmt.Errorf("error opening KeePass database: %v", err)
	}
	
	// Prompt for password to open existing database
	password, err := promptPassword("Enter password for existing KeePass database: ")
	if err != nil {
		return fmt.Errorf("error reading password: %v", err)
	}
	
	// Read keyfile data
	keyData, err := os.ReadFile(keyfilePath)
	if err != nil {
		return fmt.Errorf("error reading keyfile %s: %v", keyfilePath, err)
	}
	
	// Open the existing database
	if err := kp.OpenWithKeyData(password, keyData); err != nil {
		return fmt.Errorf("error opening KeePass database: %v", err)
	}
	
	// Check if group already exists
	if groupExists, err := kp.GroupExists(profile); err != nil {
		return fmt.Errorf("error checking if group exists: %v", err)
	} else if groupExists {
		if verbose {
			logInfo(fmt.Sprintf("Group '%s' already exists in database", profile))
		}
		return nil
	}
	
	// Create the new group
	if err := kp.CreateGroup(profile); err != nil {
		return fmt.Errorf("error creating group %s: %v", profile, err)
	}
	
	if verbose {
		logSuccess(fmt.Sprintf("Created new group: /%s/", profile))
	}
	
	// Save the database
	if err := kp.Save(); err != nil {
		return fmt.Errorf("error saving KeePass database: %v", err)
	}
	
	return nil
}

// readProfileFromSpecificYaml reads the profile from a specific YAML file
func readProfileFromSpecificYaml(yamlFile string) (string, error) {
	// Check if YAML file exists
	if _, err := os.Stat(yamlFile); os.IsNotExist(err) {
		return "", nil
	}
	
	content, err := os.ReadFile(yamlFile)
	if err != nil {
		return "", fmt.Errorf("error reading YAML file: %v", err)
	}
	
	// Split by YAML document separator
	documents := strings.Split(string(content), "---")
	if len(documents) == 0 {
		return "", nil
	}
	
	// Parse the first document (metadata)
	metadataDoc := strings.TrimSpace(documents[0])
	lines := strings.Split(metadataDoc, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "profile:") {
			// Extract profile value
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				profile := strings.TrimSpace(parts[1])
				// Remove quotes if present
				if strings.HasPrefix(profile, "\"") && strings.HasSuffix(profile, "\"") {
					profile = profile[1 : len(profile)-1]
				}
				return profile, nil
			}
		}
	}
	
	return "", nil
}
