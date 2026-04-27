//go:build windows

package wmi

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"golang.org/x/sys/windows"
)

type ProcessWatcher struct {
	ctx         context.Context
	cancel      context.CancelFunc
	events      chan *types.MonitorEvent
	subscribers []chan *types.MonitorEvent
	subMu       sync.RWMutex
	running     bool
	mu          sync.RWMutex
	lastPIDs    map[uint32]bool
	pidToName   map[uint32]string
}

type Win32_Process struct {
	Name            string
	ProcessID       uint32
	ParentProcessID uint32
	ExecutablePath  string
	CommandLine     string
}

func NewProcessWatcher() (*ProcessWatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProcessWatcher{
		ctx:         ctx,
		cancel:      cancel,
		events:      make(chan *types.MonitorEvent, 100),
		subscribers: make([]chan *types.MonitorEvent, 0),
		running:     false,
		lastPIDs:    make(map[uint32]bool),
		pidToName:   make(map[uint32]string),
	}, nil
}

func (pw *ProcessWatcher) Start() error {
	pw.mu.Lock()
	if pw.running {
		pw.mu.Unlock()
		return nil
	}
	pw.running = true
	pw.mu.Unlock()

	go pw.run()
	return nil
}

func (pw *ProcessWatcher) Stop() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if !pw.running {
		return nil
	}

	pw.cancel()
	pw.running = false

	// 不关闭 subscriber channel，由 MonitorEngine 统一管理生命周期
	pw.subMu.Lock()
	pw.subscribers = make([]chan *types.MonitorEvent, 0)
	pw.subMu.Unlock()

	return nil
}

func (pw *ProcessWatcher) Subscribe(ch chan *types.MonitorEvent) func() {
	pw.subMu.Lock()
	defer pw.subMu.Unlock()
	pw.subscribers = append(pw.subscribers, ch)
	log.Printf("[PROCESS] DEBUG: Subscribe called, subscriber count=%d, ch=%p", len(pw.subscribers), ch)
	return func() {
		pw.subMu.Lock()
		defer pw.subMu.Unlock()
		for i, c := range pw.subscribers {
			if c == ch {
				pw.subscribers = append(pw.subscribers[:i], pw.subscribers[i+1:]...)
				break
			}
		}
	}
}

func (pw *ProcessWatcher) run() {
	log.Printf("[PROCESS] ProcessWatcher run() started")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	isFirstRun := true

	for {
		select {
		case <-pw.ctx.Done():
			log.Printf("[PROCESS] ProcessWatcher run() stopping")
			return
		case <-ticker.C:
			pw.checkProcesses(isFirstRun)
			isFirstRun = false
		}
	}
}

func (pw *ProcessWatcher) checkProcesses(isFirstRun bool) {
	select {
	case <-pw.ctx.Done():
		return
	default:
	}

	var processes []Win32_Process
	err := wmi.Query("SELECT Name, ProcessID, ParentProcessID, ExecutablePath, CommandLine FROM Win32_Process", &processes)
	if err != nil {
		log.Printf("[PROCESS] WMI query failed: %v", err)
		return
	}

	log.Printf("[PROCESS] WMI query returned %d processes (firstRun=%v)", len(processes), isFirstRun)

	currentPIDs := make(map[uint32]bool)
	currentProcs := make(map[uint32]*Win32_Process)

	for i := range processes {
		p := &processes[i]
		currentPIDs[p.ProcessID] = true
		currentProcs[p.ProcessID] = p
	}

	pw.mu.Lock()
	newProcessCount := 0
	exitProcessCount := 0
	for pid, p := range currentProcs {
		pw.pidToName[pid] = p.Name
		_, existed := pw.lastPIDs[pid]
		if !existed {
			event := pw.createProcessEvent(p, true)
			if event != nil {
				log.Printf("[PROCESS] DEBUG: Detected new process, calling publishEvent, subscribers=%d", len(pw.subscribers))
				pw.publishEvent(event)
				newProcessCount++
				log.Printf("[PROCESS] New process detected: Name=%s, PID=%d, Path=%s", p.Name, p.ProcessID, p.ExecutablePath)
			}
		}
	}

	for pid := range pw.lastPIDs {
		if !currentPIDs[pid] {
			procName := pw.pidToName[pid]
			if procName == "" {
				procName = "Unknown"
			}
			event := pw.createProcessExitEvent(pid, procName)
			if event != nil {
				pw.publishEvent(event)
				exitProcessCount++
				log.Printf("[PROCESS] Process exited: Name=%s, PID=%d", procName, pid)
			}
			delete(pw.pidToName, pid)
		}
	}
	pw.lastPIDs = currentPIDs
	pw.mu.Unlock()

	if newProcessCount > 0 {
		log.Printf("[PROCESS] Summary: %d new processes, %d exited", newProcessCount, exitProcessCount)
	}
}

func (pw *ProcessWatcher) createProcessEvent(p *Win32_Process, isNew bool) *types.MonitorEvent {
	severity := types.SeverityInfo
	pathLower := strings.ToLower(p.ExecutablePath)
	cmdLower := strings.ToLower(p.CommandLine)

	for _, indicator := range types.SuspiciousProcessIndicators {
		if strings.Contains(pathLower, strings.ToLower(indicator)) ||
			strings.Contains(cmdLower, strings.ToLower(indicator)) {
			severity = types.SeverityMedium
			break
		}
	}

	username := getProcessUser(p.ProcessID)

	data := make(map[string]interface{})
	data["pid"] = p.ProcessID
	data["ppid"] = p.ParentProcessID
	data["process_name"] = p.Name
	data["path"] = p.ExecutablePath
	data["command_line"] = p.CommandLine
	data["user"] = username
	data["is_new"] = isNew

	return &types.MonitorEvent{
		ID:        fmt.Sprintf("proc-%d-%d", p.ProcessID, time.Now().UnixNano()),
		Type:      types.EventTypeProcess,
		Timestamp: time.Now(),
		Severity:  severity,
		Data:      data,
	}
}

func (pw *ProcessWatcher) createProcessExitEvent(pid uint32, processName string) *types.MonitorEvent {
	data := make(map[string]interface{})
	data["pid"] = pid
	data["process_name"] = processName
	data["is_new"] = false

	return &types.MonitorEvent{
		ID:        fmt.Sprintf("proc-exit-%d-%d", pid, time.Now().UnixNano()),
		Type:      types.EventTypeProcess,
		Timestamp: time.Now(),
		Severity:  types.SeverityInfo,
		Data:      data,
	}
}

func (pw *ProcessWatcher) publishEvent(event *types.MonitorEvent) {
	pw.subMu.RLock()
	defer pw.subMu.RUnlock()

	log.Printf("[PROCESS] DEBUG: publishEvent called, subscriber count=%d, event type=%s", len(pw.subscribers), event.Type)
	for _, ch := range pw.subscribers {
		select {
		case ch <- event:
		case <-time.After(1 * time.Second):
			log.Printf("[PROCESS] WARNING: Failed to send event to subscriber (timeout)")
		}
	}
}

func getProcessUser(pid uint32) string {
	if pid == 0 {
		return "SYSTEM"
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "Unknown"
	}
	defer windows.CloseHandle(hProcess)

	var tokenHandle windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &tokenHandle)
	if err != nil {
		return "Unknown"
	}
	defer windows.CloseHandle(windows.Handle(tokenHandle))

	var bufSize uint32
	windows.GetTokenInformation(tokenHandle, windows.TokenUser, nil, 0, &bufSize)

	if bufSize == 0 {
		return "Unknown"
	}

	buf := make([]byte, bufSize)
	var returnedSize uint32
	if err := windows.GetTokenInformation(tokenHandle, windows.TokenUser, &buf[0], bufSize, &returnedSize); err != nil {
		return "Unknown"
	}

	tokenUser := (*windows.Tokenuser)(unsafe.Pointer(&buf[0]))

	var name [256]uint16
	var domain [256]uint16
	var nameSize uint32 = 256
	var domainSize uint32 = 256
	var use uint32

	_ = windows.LookupAccountSid(nil, tokenUser.User.Sid, &name[0], &nameSize, &domain[0], &domainSize, &use)
	domainStr := windows.UTF16ToString(domain[:nameSize])
	nameStr := windows.UTF16ToString(name[:nameSize])
	if domainStr != "" {
		return domainStr + "\\" + nameStr
	}
	if nameStr != "" {
		return nameStr
	}

	return "Unknown"
}
