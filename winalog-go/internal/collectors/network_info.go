//go:build windows

package collectors

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"golang.org/x/sys/windows"
)

type NetworkInfoCollector struct {
	BaseCollector
}

type NetConnection struct {
	PID         int
	Protocol    string
	LocalAddr   string
	LocalPort   int
	RemoteAddr  string
	RemotePort  int
	State       string
	ProcessName string
}

func NewNetworkInfoCollector() *NetworkInfoCollector {
	return &NetworkInfoCollector{
		BaseCollector: BaseCollector{
			info: CollectorInfo{
				Name:          "network_info",
				Description:   "Collect network connection information",
				RequiresAdmin: false,
				Version:       "1.0.0",
			},
		},
	}
}

func (c *NetworkInfoCollector) Collect(ctx context.Context) ([]interface{}, error) {
	connections, err := c.collectNetworkInfo()
	if err != nil {
		return nil, err
	}
	interfaces := make([]interface{}, len(connections))
	for i, n := range connections {
		interfaces[i] = n
	}
	return interfaces, nil
}

func (c *NetworkInfoCollector) collectNetworkInfo() ([]*types.NetworkConnection, error) {
	return collectNetworkViaNetstat()
}

func collectNetworkViaNetstat() ([]*types.NetworkConnection, error) {
	processNames := getProcessNameMap()

	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	connections := make([]*types.NetworkConnection, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "TCP") && !strings.HasPrefix(line, "UDP") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		protocol := fields[0]
		localAddr := fields[1]
		remoteAddr := fields[2]
		
		var pid int
		state := ""

		if protocol == "TCP" {
			if len(fields) < 5 {
				continue
			}
			state = fields[3]
			pid, _ = strconv.Atoi(fields[4])
		} else {
			pid, _ = strconv.Atoi(fields[3])
			state = "Listen"
		}

		processName := "Unknown"
		if name, ok := processNames[pid]; ok {
			processName = name
		}

		localIP, localPort := parseAddr(localAddr)
		remoteIP, remotePort := parseAddr(remoteAddr)

		if protocol == "UDP" && remoteIP == "*:*" {
			remoteIP = "*"
			remotePort = 0
		}

		conn := &types.NetworkConnection{
			Protocol:    strings.ToUpper(protocol),
			LocalAddr:   localIP,
			LocalPort:   localPort,
			RemoteAddr:  remoteIP,
			RemotePort:  remotePort,
			State:       state,
			PID:         int32(pid),
			ProcessName: processName,
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

func parseAddr(addr string) (string, int) {
	if addr == "*:*" || addr == "[::]:*" || addr == "0.0.0.0:*" {
		return "*", 0
	}

	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, 0
	}

	ip := addr[:idx]
	portStr := addr[idx+1:]
	port, _ := strconv.Atoi(portStr)

	if ip == "::" {
		ip = "*"
	} else if ip == "0.0.0.0" {
		ip = "*"
	}

	return ip, port
}

func ListNetworkConnections() ([]NetConnection, error) {
	typesConn, err := collectNetworkViaNetstat()
	if err != nil {
		return []NetConnection{}, err
	}

	result := make([]NetConnection, 0, len(typesConn))
	for _, c := range typesConn {
		result = append(result, NetConnection{
			PID:         int(c.PID),
			Protocol:    c.Protocol,
			LocalAddr:   c.LocalAddr,
			LocalPort:   c.LocalPort,
			RemoteAddr:  c.RemoteAddr,
			RemotePort:  c.RemotePort,
			State:       c.State,
			ProcessName: c.ProcessName,
		})
	}
	return result, nil
}

func GetTCPConnections() ([]NetConnection, error) {
	all, err := ListNetworkConnections()
	if err != nil {
		return nil, err
	}
	result := make([]NetConnection, 0)
	for _, c := range all {
		if c.Protocol == "TCP" {
			result = append(result, c)
		}
	}
	return result, nil
}

func GetUDPEndpoints() ([]NetConnection, error) {
	all, err := ListNetworkConnections()
	if err != nil {
		return nil, err
	}
	result := make([]NetConnection, 0)
	for _, c := range all {
		if c.Protocol == "UDP" {
			result = append(result, c)
		}
	}
	return result, nil
}

func getProcessNameMap() map[int]string {
	result := make(map[int]string)

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return result
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return result
	}

	for {
		result[int(entry.ProcessID)] = windows.UTF16ToString(entry.ExeFile[:])
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return result
}
