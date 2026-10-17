// SPDX-License-Identifier: Apache-2.0
// scanner-guard is the PID-1 deadline boundary inside an offline scanner
// container. It cannot accept an arbitrary command or execute repository code.
package main

import (
	"aegis.local/alpha/scanners"
	"aegis.local/source"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func program(tool string) (string, []string, error) { return programWith(tool, databaseMounted) }

// databaseMounted reports whether the executor mounted an advisory database
// directory for this tool; the guard never takes a path from its arguments.
func databaseMounted(tool string) bool {
	path, e := scanners.DatabaseContainerPath(tool)
	if e != nil {
		return false
	}
	info, e := os.Stat(path)
	return e == nil && info.IsDir()
}

func programWith(tool string, mounted func(string) bool) (string, []string, error) {
	invocation, e := scanners.BuildInvocation(tool)
	if _, advisory := scanners.DatabaseContainerPath(tool); advisory == nil && mounted(tool) {
		invocation, e = scanners.BuildDatabaseInvocation(tool)
	}
	if e != nil {
		return "", nil, e
	}
	switch tool {
	case "semgrep_ce":
		return "semgrep", invocation.Args[1:], nil
	case "osv_v2":
		return "/osv-scanner", invocation.Args, nil
	case "trivy":
		return "trivy", invocation.Args, nil
	case "syft":
		return "/syft", invocation.Args, nil
	case "bandit":
		return "bandit", invocation.Args, nil
	case "gitleaks":
		return "gitleaks", invocation.Args, nil
	default:
		return "", nil, fmt.Errorf("guard scanner unsupported")
	}
}

type boundedStream struct {
	mu     sync.Mutex
	writer io.Writer
	used   int
	cancel context.CancelFunc
}

func (w *boundedStream) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.used+len(p) > scanners.MaxOutput {
		w.cancel()
		return 0, fmt.Errorf("scanner stream budget exceeded")
	}
	w.used += len(p)
	return w.writer.Write(p)
}

var errExpired = errors.New("scanner absolute deadline expired")

// startupDeadline rejects late daemon starts and caps remaining execution by
// both the fixed tool budget and the original absolute deadline. The local host
// clock is part of the trusted operator boundary, not a remote attestation.
func startupDeadline(raw string, seconds int, now time.Time) (time.Time, error) {
	if seconds < 1 || seconds > 120 || len(raw) > 35 {
		return time.Time{}, fmt.Errorf("invalid scanner deadline")
	}
	deadline, e := time.Parse(time.RFC3339Nano, raw)
	if e != nil || raw != deadline.UTC().Format(time.RFC3339Nano) || deadline.After(now.Add(15*time.Minute)) {
		return time.Time{}, fmt.Errorf("invalid scanner deadline")
	}
	if !deadline.After(now) {
		return time.Time{}, errExpired
	}
	budget := now.Add(time.Duration(seconds) * time.Second)
	if budget.Before(deadline) {
		deadline = budget
	}
	return deadline, nil
}

func main() {
	if len(os.Args) != 4 || os.Getpid() != 1 || os.Geteuid() <= 0 {
		fmt.Fprintln(os.Stderr, "scanner guard requires non-root container PID 1 and a fixed tool")
		os.Exit(125)
	}
	seconds, e := strconv.Atoi(os.Args[2])
	if e != nil || seconds < 1 || seconds > 120 {
		os.Exit(125)
	}
	deadline, e := startupDeadline(os.Args[3], seconds, time.Now())
	if errors.Is(e, errExpired) {
		os.Exit(124)
	}
	if e != nil {
		os.Exit(125)
	}
	binary, args, e := program(os.Args[1])
	if e != nil {
		os.Exit(125)
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	ctx, cancel := context.WithDeadline(signalCtx, deadline)
	defer cancel()
	manifestFile, e := os.Open("/aegis/input-manifest.json")
	if e != nil {
		os.Exit(125)
	}
	manifestBytes, e := io.ReadAll(io.LimitReader(manifestFile, scanners.MaxOutput+1))
	manifestFile.Close()
	if e != nil || len(manifestBytes) > scanners.MaxOutput {
		os.Exit(125)
	}
	var manifest source.Manifest
	if json.Unmarshal(manifestBytes, &manifest) != nil {
		os.Exit(125)
	}
	root, e := os.OpenRoot("/src")
	if e != nil {
		os.Exit(125)
	}
	e = source.ValidateSnapshot(ctx, root, manifest)
	root.Close()
	if e != nil {
		if ctx.Err() != nil {
			os.Exit(124)
		}
		os.Exit(125)
	}
	if os.Args[1] == "semgrep_ce" {
		f, e := os.Open("/aegis/rules-manifest.json")
		if e != nil {
			os.Exit(125)
		}
		b, e := io.ReadAll(io.LimitReader(f, scanners.MaxOutput+1))
		f.Close()
		if e != nil || len(b) > scanners.MaxOutput {
			os.Exit(125)
		}
		var rules source.Manifest
		if json.Unmarshal(b, &rules) != nil {
			os.Exit(125)
		}
		root, e := os.OpenRoot("/rules")
		if e != nil {
			os.Exit(125)
		}
		e = source.ValidateSnapshot(ctx, root, rules)
		root.Close()
		if e != nil {
			if ctx.Err() != nil {
				os.Exit(124)
			}
			os.Exit(125)
		}
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		os.Exit(124)
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		e := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return nil
		}
		return e
	}
	command.WaitDelay = 2 * time.Second
	command.Stdout = &boundedStream{writer: os.Stdout, cancel: cancel}
	command.Stderr = &boundedStream{writer: os.Stderr, cancel: cancel}
	e = command.Run()
	if ctx.Err() != nil {
		os.Exit(124)
	}
	if e != nil {
		if command.ProcessState != nil && command.ProcessState.ExitCode() > 0 {
			os.Exit(command.ProcessState.ExitCode())
		}
		os.Exit(125)
	}
	// PID-1 exit also ends descendants that escaped the child's process group.
}
