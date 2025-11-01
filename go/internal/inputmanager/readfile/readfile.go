package readfile

import (
"os"
"gopkg.in/yaml.v3"
)

type FileReader interface {
ReadYAML(path string) (map[string]interface{}, error)
ReadRaw(path string) ([]byte, error)
}

type StandardFileReader struct{}

func NewStandardFileReader() FileReader {
return &StandardFileReader{}
}

func (f *StandardFileReader) ReadYAML(path string) (map[string]interface{}, error) {
data, err := os.ReadFile(path)
if err != nil {
return nil, err
}
var result map[string]interface{}
if err := yaml.Unmarshal(data, &result); err != nil {
return nil, err
}
return result, nil
}

func (f *StandardFileReader) ReadRaw(path string) ([]byte, error) {
return os.ReadFile(path)
}
