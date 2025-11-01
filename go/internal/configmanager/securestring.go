package configmanager

import (
"crypto/rand"
"runtime"
)

type SecureString struct {
data []byte
}

func NewSecureString(value string) *SecureString {
s := &SecureString{data: []byte(value)}
runtime.SetFinalizer(s, (*SecureString).Clear)
return s
}

func (s *SecureString) String() string {
if s.data == nil {
return ""
}
return string(s.data)
}

func (s *SecureString) Clear() {
if s.data == nil {
return
}
rand.Read(s.data)
for i := range s.data {
s.data[i] = 0
}
s.data = nil
}
