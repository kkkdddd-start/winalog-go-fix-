package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type PowerShellResult struct {
	Output string
	Error  error
}

func NewPowerShellResult(output string, err error) *PowerShellResult {
	return &PowerShellResult{
		Output: output,
		Error:  err,
	}
}

func (r *PowerShellResult) Success() bool {
	return r.Error == nil
}

func (r *PowerShellResult) String() string {
	if r.Error != nil {
		return fmt.Sprintf("Error: %v, Output: %s", r.Error, r.Output)
	}
	return r.Output
}

const DefaultPowerShellTimeout = 120 * time.Second

func RunPowerShell(command string) *PowerShellResult {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultPowerShellTimeout)
	defer cancel()
	return RunPowerShellWithContext(ctx, command)
}

func RunPowerShellWithTimeout(command string, timeout time.Duration) *PowerShellResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunPowerShellWithContext(ctx, command)
}

func RunPowerShellAsync(ctx context.Context, command string) *PowerShellResult {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "+command)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &PowerShellResult{
		Output: strings.TrimSpace(out.String()),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("powershell timeout: %w", ctx.Err())
		} else {
			result.Error = fmt.Errorf("powershell error: %w, stderr: %s", err, stderr.String())
		}
	}

	return result
}

func RunPowerShellWithContext(ctx context.Context, command string) *PowerShellResult {
	return RunPowerShellAsync(ctx, command)
}

func RunPowerShellScript(scriptPath string, args ...string) *PowerShellResult {
	cmdArgs := append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; . '" + scriptPath + "'"}, args...)
	cmd := exec.Command("powershell", cmdArgs...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &PowerShellResult{
		Output: strings.TrimSpace(out.String()),
	}

	if err != nil {
		result.Error = fmt.Errorf("script error: %w, stderr: %s", err, stderr.String())
	}

	return result
}

func EncodeToBase64(script string) string {
	return base64.StdEncoding.EncodeToString([]byte(script))
}

func DecodeFromBase64(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	return string(decoded), nil
}

func RunEncodedPowerShell(encodedScript string) *PowerShellResult {
	command := fmt.Sprintf("$decoded = [System.Convert]::FromBase64String('%s'); $script = [System.Text.Encoding]::Unicode.GetString($decoded); Invoke-Expression $script", encodedScript)
	return RunPowerShell(command)
}

func TestPowerShellAvailable() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "echo test")
	err := cmd.Run()
	return err == nil
}

func GetPowerShellVersion() string {
	result := RunPowerShell("$PSVersionTable.PSVersion.ToString()")
	if result.Success() {
		return result.Output
	}
	return "unknown"
}

func RunCommand(command string) (string, error) {
	result := RunPowerShell(command)
	if result.Error != nil {
		return "", result.Error
	}
	return result.Output, nil
}

func RunCommandWithArgs(command string, args ...string) (string, error) {
	fullCommand := command
	for _, arg := range args {
		fullCommand += " " + arg
	}
	return RunCommand(fullCommand)
}

type PowerShellBuilder struct {
	commands []string
}

func NewPowerShellBuilder() *PowerShellBuilder {
	return &PowerShellBuilder{
		commands: make([]string, 0),
	}
}

func (b *PowerShellBuilder) Add(command string) *PowerShellBuilder {
	b.commands = append(b.commands, command)
	return b
}

func (b *PowerShellBuilder) AddWithSemicolon(command string) *PowerShellBuilder {
	b.commands = append(b.commands, command+";")
	return b
}

func (b *PowerShellBuilder) Build() string {
	return strings.Join(b.commands, " ")
}

func (b *PowerShellBuilder) Run() *PowerShellResult {
	return RunPowerShell(b.Build())
}
