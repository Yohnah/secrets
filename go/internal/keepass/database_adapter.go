package keepass

import (
"fmt"
"strings"

"github.com/tobischo/gokeepasslib/v3"
)

// DatabaseAdapter adapts gokeepasslib.Database to implement validator.KeePassManager interface
// This allows SecretsManager to pass database to ValidatorManager for duplicate validation
type DatabaseAdapter struct {
db *gokeepasslib.Database
}

// NewDatabaseAdapter creates a new adapter for gokeepasslib.Database
func NewDatabaseAdapter(db *gokeepasslib.Database) *DatabaseAdapter {
return &DatabaseAdapter{db: db}
}

// GetRootGroups returns names of all groups at ROOT level
func (a *DatabaseAdapter) GetRootGroups() ([]string, error) {
if a.db == nil || a.db.Content == nil {
return []string{}, nil
}

var groups []string
for _, group := range a.db.Content.Root.Groups {
groups = append(groups, group.Name)
}
return groups, nil
}

// GetGroupsByParent returns names of child groups within a parent group path
// parentPath format: "profile" or "profile/HEAD" or "profile/HEAD/production"
func (a *DatabaseAdapter) GetGroupsByParent(parentPath string) ([]string, error) {
if a.db == nil || a.db.Content == nil {
return []string{}, nil
}

group := a.findGroupByPath(parentPath)
if group == nil {
return []string{}, nil
}

var groups []string
for _, childGroup := range group.Groups {
groups = append(groups, childGroup.Name)
}
return groups, nil
}

// GetEntriesByGroup returns names of entries within a group
// groupPath format: "profile/HEAD/production"
func (a *DatabaseAdapter) GetEntriesByGroup(groupPath string) ([]string, error) {
if a.db == nil || a.db.Content == nil {
return []string{}, nil
}

group := a.findGroupByPath(groupPath)
if group == nil {
return []string{}, nil
}

var entries []string
for _, entry := range group.Entries {
title := a.getEntryField(&entry, "Title")
if title != "" {
entries = append(entries, title)
}
}
return entries, nil
}

// GetFieldsByEntry returns names of fields within an entry
// entryPath format: "profile/HEAD/production/db_credentials"
func (a *DatabaseAdapter) GetFieldsByEntry(entryPath string) ([]string, error) {
if a.db == nil || a.db.Content == nil {
return []string{}, nil
}

entry := a.findEntryByPath(entryPath)
if entry == nil {
return []string{}, nil
}

var fields []string

// Standard fields
for _, value := range entry.Values {
if value.Key != "" {
fields = append(fields, value.Key)
}
}

// Attachments (format: attachments/filename)
for _, binary := range entry.Binaries {
if binary.Name != "" {
fields = append(fields, fmt.Sprintf("attachments/%s", binary.Name))
}
}

return fields, nil
}

// Helper: findGroupByPath navigates group hierarchy to find a group by path
func (a *DatabaseAdapter) findGroupByPath(path string) *gokeepasslib.Group {
if a.db == nil || a.db.Content == nil {
return nil
}

if path == "" {
return nil
}

parts := strings.Split(path, "/")
currentGroups := a.db.Content.Root.Groups

for _, partName := range parts {
found := false
for i := range currentGroups {
if currentGroups[i].Name == partName {
// If this is the last part, return this group
if partName == parts[len(parts)-1] {
return &currentGroups[i]
}
// Otherwise, continue searching in children
currentGroups = currentGroups[i].Groups
found = true
break
}
}
if !found {
return nil
}
}

return nil
}

// Helper: findEntryByPath navigates to find an entry by full path
// entryPath format: "profile/HEAD/production/entry_name"
func (a *DatabaseAdapter) findEntryByPath(entryPath string) *gokeepasslib.Entry {
if a.db == nil || a.db.Content == nil {
return nil
}

parts := strings.Split(entryPath, "/")
if len(parts) < 2 {
return nil // Need at least group/entry
}

// Navigate to parent group (all parts except last)
groupPath := strings.Join(parts[:len(parts)-1], "/")
group := a.findGroupByPath(groupPath)
if group == nil {
return nil
}

// Find entry by name (last part)
entryName := parts[len(parts)-1]
for i := range group.Entries {
title := a.getEntryField(&group.Entries[i], "Title")
if title == entryName {
return &group.Entries[i]
}
}

return nil
}

// Helper: getEntryField extracts a field value from entry
func (a *DatabaseAdapter) getEntryField(entry *gokeepasslib.Entry, fieldName string) string {
for _, value := range entry.Values {
if value.Key == fieldName {
return value.Value.Content
}
}
return ""
}
