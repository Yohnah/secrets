package cli

import "github.com/spf13/cobra"

type CliReader interface {
GetCommand() string
GetStringFlag(name string) (string, error)
GetBoolFlag(name string) (bool, error)
SetCommand(cmd *cobra.Command)
}

type CobraCliReader struct {
cmd *cobra.Command
}

func NewCobraCliReader() CliReader {
return &CobraCliReader{}
}

func (r *CobraCliReader) SetCommand(cmd *cobra.Command) {
r.cmd = cmd
}

func (r *CobraCliReader) GetCommand() string {
if r.cmd == nil {
return ""
}
return r.cmd.Name()
}

func (r *CobraCliReader) GetStringFlag(name string) (string, error) {
if r.cmd == nil {
return "", nil
}
return r.cmd.Flags().GetString(name)
}

func (r *CobraCliReader) GetBoolFlag(name string) (bool, error) {
if r.cmd == nil {
return false, nil
}
return r.cmd.Flags().GetBool(name)
}
