//go:build windows

package poll

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kkkdddd-start/winalog-go/internal/monitor/types"
	"golang.org/x/sys/windows"
)

type NetworkPoller struct {
	ctx            context.Context
	cancel         context.CancelFunc
	interval       time.Duration
	prevTCPIPv4    map[string]*types.ConnectionInfo
	prevTCPIPv6    map[string]*types.ConnectionInfo
	prevUDPIPv4    map[string]*types.ConnectionInfo
	prevUDPIPv6    map[string]*types.ConnectionInfo
	listeningPorts map[uint16]uint32
	events         chan *types.MonitorEvent
	subscribers    []chan *types.MonitorEvent
	subMu          sync.RWMutex
	running        bool
	mu             sync.RWMutex
	wg             sync.WaitGroup
}

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  [4]byte
	LocalPort  uint32
	RemoteAddr [4]byte
	RemotePort uint32
	PID        uint32
}

type MIB_TCP6ROW_OWNER_PID struct {
	LocalAddr  [16]byte
	LocalPort  uint32
	RemoteAddr [16]byte
	RemotePort uint32
	State      uint32
	PID        uint32
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr [4]byte
	LocalPort uint32
	PID       uint32
}

type MIB_UDP6ROW_OWNER_PID struct {
	LocalAddr [16]byte
	LocalPort uint32
	PID       uint32
}

type Addr struct {
	IP   string
	Port uint16
}

var (
	iphlpapi      *syscall.DLL
	procTcpTable  *syscall.Proc
	procUdpTable  *syscall.Proc
	procTcp6Table *syscall.Proc
	procUdp6Table *syscall.Proc
	dllLoadOnce   sync.Once
	dllInitErr    error
)

func initDLL() error {
	dllLoadOnce.Do(func() {
		var err error
		iphlpapi, err = syscall.LoadDLL("iphlpapi.dll")
		if err != nil {
			dllInitErr = fmt.Errorf("failed to load iphlpapi.dll: %w", err)
			return
		}
		procTcpTable, err = iphlpapi.FindProc("GetExtendedTcpTable")
		if err != nil {
			dllInitErr = fmt.Errorf("failed to find GetExtendedTcpTable: %w", err)
			return
		}
		procUdpTable, err = iphlpapi.FindProc("GetExtendedUdpTable")
		if err != nil {
			dllInitErr = fmt.Errorf("failed to find GetExtendedUdpTable: %w", err)
			return
		}
		procTcp6Table, err = iphlpapi.FindProc("GetExtendedTcp6Table")
		if err != nil {
			log.Printf("[WARN] GetExtendedTcp6Table not available: %v", err)
		}
		procUdp6Table, err = iphlpapi.FindProc("GetExtendedUdp6Table")
		if err != nil {
			log.Printf("[WARN] GetExtendedUdp6Table not available: %v", err)
		}
	})
	return dllInitErr
}

func getTCPConnections() ([]*types.ConnectionInfo, error) {
	if err := initDLL(); err != nil {
		return nil, err
	}

	var size uint32
	ret, _, _ := procTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
	if ret != 0 && ret != 122 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	numEntries := uint32(buf[0]) | (uint32(buf[1]) << 8) | (uint32(buf[2]) << 16) | (uint32(buf[3]) << 24)
	offset := 4

	connections := make([]*types.ConnectionInfo, 0)
	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		offset += int(unsafe.Sizeof(*row))

		localIP := net.IP(row.LocalAddr[:]).String()
		remoteIP := net.IP(row.RemoteAddr[:]).String()
		localPort := windows.Ntohs(uint16(row.LocalPort))
		remotePort := windows.Ntohs(uint16(row.RemotePort))

		conn := &types.ConnectionInfo{
			Protocol:   "TCP",
			LocalAddr:  fmt.Sprintf("%s:%d", localIP, localPort),
			RemoteAddr: fmt.Sprintf("%s:%d", remoteIP, remotePort),
			State:      row.State,
			PID:        row.PID,
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

func getTCPIPv6Connections() ([]*types.ConnectionInfo, error) {
	if procTcp6Table == nil {
		return []*types.ConnectionInfo{}, nil
	}

	var size uint32
	ret, _, _ := procTcp6Table.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET6, 5, 0)
	if ret != 0 && ret != 122 {
		return nil, fmt.Errorf("GetExtendedTcp6Table failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procTcp6Table.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET6, 5, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcp6Table failed: %d", ret)
	}

	numEntries := uint32(buf[0]) | (uint32(buf[1]) << 8) | (uint32(buf[2]) << 16) | (uint32(buf[3]) << 24)
	offset := 4

	connections := make([]*types.ConnectionInfo, 0)
	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		offset += int(unsafe.Sizeof(*row))

		localIP := net.IP(row.LocalAddr[:]).String()
		remoteIP := net.IP(row.RemoteAddr[:]).String()
		localPort := windows.Ntohs(uint16(row.LocalPort))
		remotePort := windows.Ntohs(uint16(row.RemotePort))

		conn := &types.ConnectionInfo{
			Protocol:   "TCPv6",
			LocalAddr:  fmt.Sprintf("[%s]:%d", localIP, localPort),
			RemoteAddr: fmt.Sprintf("[%s]:%d", remoteIP, remotePort),
			State:      row.State,
			PID:        row.PID,
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

func getUDPConnections() ([]*types.ConnectionInfo, error) {
	if err := initDLL(); err != nil {
		return nil, err
	}

	var size uint32
	ret, _, _ := procUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 1, 0)
	if ret != 0 && ret != 122 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 1, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}

	numEntries := uint32(buf[0]) | (uint32(buf[1]) << 8) | (uint32(buf[2]) << 16) | (uint32(buf[3]) << 24)
	offset := 4

	connections := make([]*types.ConnectionInfo, 0)
	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		offset += int(unsafe.Sizeof(*row))

		localIP := net.IP(row.LocalAddr[:]).String()
		localPort := windows.Ntohs(uint16(row.LocalPort))

		conn := &types.ConnectionInfo{
			Protocol:   "UDP",
			LocalAddr:  fmt.Sprintf("%s:%d", localIP, localPort),
			RemoteAddr: "*:*",
			State:      0,
			PID:        row.PID,
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

func getUDPIPv6Connections() ([]*types.ConnectionInfo, error) {
	if procUdp6Table == nil {
		return []*types.ConnectionInfo{}, nil
	}

	var size uint32
	ret, _, _ := procUdp6Table.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET6, 1, 0)
	if ret != 0 && ret != 122 {
		return nil, fmt.Errorf("GetExtendedUdp6Table failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procUdp6Table.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET6, 1, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdp6Table failed: %d", ret)
	}

	numEntries := uint32(buf[0]) | (uint32(buf[1]) << 8) | (uint32(buf[2]) << 16) | (uint32(buf[3]) << 24)
	offset := 4

	connections := make([]*types.ConnectionInfo, 0)
	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))
		offset += int(unsafe.Sizeof(*row))

		localIP := net.IP(row.LocalAddr[:]).String()
		localPort := windows.Ntohs(uint16(row.LocalPort))

		conn := &types.ConnectionInfo{
			Protocol:   "UDPv6",
			LocalAddr:  fmt.Sprintf("[%s]:%d", localIP, localPort),
			RemoteAddr: "*:*",
			State:      0,
			PID:        row.PID,
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

func NewNetworkPoller(interval time.Duration) (*NetworkPoller, error) {
	if err := initDLL(); err != nil {
		return nil, err
	}

	if interval <= 0 {
		interval = 3 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkPoller{
		ctx:            ctx,
		cancel:         cancel,
		interval:       interval,
		prevTCPIPv4:    make(map[string]*types.ConnectionInfo),
		prevTCPIPv6:    make(map[string]*types.ConnectionInfo),
		prevUDPIPv4:    make(map[string]*types.ConnectionInfo),
		prevUDPIPv6:    make(map[string]*types.ConnectionInfo),
		listeningPorts: make(map[uint16]uint32),
		events:         make(chan *types.MonitorEvent, 100),
		subscribers:    make([]chan *types.MonitorEvent, 0),
		running:        false,
	}, nil
}

func (np *NetworkPoller) Start() error {
	np.mu.Lock()
	defer np.mu.Unlock()

	if np.running {
		return nil
	}
	np.running = true

	np.wg.Add(1)
	go np.run()
	return nil
}

func (np *NetworkPoller) Stop() error {
	np.mu.Lock()
	if !np.running {
		np.mu.Unlock()
		return nil
	}

	np.cancel()
	np.running = false
	np.mu.Unlock()

	np.wg.Wait()

	np.subMu.Lock()
	np.subscribers = make([]chan *types.MonitorEvent, 0)
	np.subMu.Unlock()

	return nil
}

func (np *NetworkPoller) Subscribe(ch chan *types.MonitorEvent) func() {
	np.subMu.Lock()
	defer np.subMu.Unlock()
	np.subscribers = append(np.subscribers, ch)
	return func() {
		np.subMu.Lock()
		defer np.subMu.Unlock()
		for i, c := range np.subscribers {
			if c == ch {
				np.subscribers = append(np.subscribers[:i], np.subscribers[i+1:]...)
				break
			}
		}
	}
}

func (np *NetworkPoller) run() {
	defer np.wg.Done()
	ticker := time.NewTicker(np.interval)
	defer ticker.Stop()

	np.pollConnections()

	for {
		select {
		case <-np.ctx.Done():
			return
		case <-ticker.C:
			np.pollConnections()
		}
	}
}

func (np *NetworkPoller) pollConnections() {
	select {
	case <-np.ctx.Done():
		return
	default:
	}

	currentTCPIPv4 := make(map[string]*types.ConnectionInfo)
	currentTCPIPv6 := make(map[string]*types.ConnectionInfo)
	currentUDPIPv4 := make(map[string]*types.ConnectionInfo)
	currentUDPIPv6 := make(map[string]*types.ConnectionInfo)

	tcpConns, err := getTCPConnections()
	if err != nil {
		log.Printf("[ERROR] getTCPConnections failed: %v", err)
	} else {
		for _, conn := range tcpConns {
			key := fmt.Sprintf("tcp4-%s-%s", conn.LocalAddr, conn.RemoteAddr)
			currentTCPIPv4[key] = conn
			if conn.State == 5 {
				port := extractPort(conn.LocalAddr)
				if port > 0 {
					np.listeningPorts[port] = conn.PID
				}
			}
		}
	}

	tcp6Conns, err := getTCPIPv6Connections()
	if err != nil {
		log.Printf("[ERROR] getTCPIPv6Connections failed: %v", err)
	} else {
		for _, conn := range tcp6Conns {
			key := fmt.Sprintf("tcp6-%s-%s", conn.LocalAddr, conn.RemoteAddr)
			currentTCPIPv6[key] = conn
			if conn.State == 5 {
				port := extractPort(conn.LocalAddr)
				if port > 0 {
					np.listeningPorts[port] = conn.PID
				}
			}
		}
	}

	udpConns, err := getUDPConnections()
	if err != nil {
		log.Printf("[ERROR] getUDPConnections failed: %v", err)
	} else {
		for _, conn := range udpConns {
			key := fmt.Sprintf("udp4-%s", conn.LocalAddr)
			currentUDPIPv4[key] = conn
		}
	}

	udp6Conns, err := getUDPIPv6Connections()
	if err != nil {
		log.Printf("[ERROR] getUDPIPv6Connections failed: %v", err)
	} else {
		for _, conn := range udp6Conns {
			key := fmt.Sprintf("udp6-%s", conn.LocalAddr)
			currentUDPIPv6[key] = conn
		}
	}

	np.mu.Lock()
	np.diffAndPublish(currentTCPIPv4, np.prevTCPIPv4, true, "TCP")
	np.diffAndPublish(currentTCPIPv6, np.prevTCPIPv6, true, "TCPv6")
	np.diffAndPublish(currentUDPIPv4, np.prevUDPIPv4, false, "UDP")
	np.diffAndPublish(currentUDPIPv6, np.prevUDPIPv6, false, "UDPv6")

	np.prevTCPIPv4 = currentTCPIPv4
	np.prevTCPIPv6 = currentTCPIPv6
	np.prevUDPIPv4 = currentUDPIPv4
	np.prevUDPIPv6 = currentUDPIPv6
	np.mu.Unlock()
}

func (np *NetworkPoller) diffAndPublish(current, previous map[string]*types.ConnectionInfo, isTCP bool, protocol string) {
	for key, conn := range current {
		if _, existed := previous[key]; !existed {
			event := np.createNetworkEvent(conn, isTCP)
			if event != nil {
				np.publishEvent(event)
			}
		}
	}

	for key, conn := range previous {
		if _, exists := current[key]; !exists {
			event := np.createNetworkCloseEvent(conn, isTCP)
			if event != nil {
				np.publishEvent(event)
			}
		}
	}
}

func extractPort(addr string) uint16 {
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		var port uint16
		fmt.Sscanf(parts[len(parts)-1], "%d", &port)
		return port
	}
	return 0
}

func (np *NetworkPoller) createNetworkEvent(conn *types.ConnectionInfo, isTCP bool) *types.MonitorEvent {
	severity := types.SeverityInfo
	processName, processPath := getProcessNameAndPath(conn.PID)

	localIP, localPort := splitAddr(conn.LocalAddr)
	remoteIP, remotePort := splitAddr(conn.RemoteAddr)

	if conn.State == 2 {
		severity = types.SeverityLow
	}

	for _, port := range types.SuspiciousPorts {
		if remotePort != 0 && remotePort == port {
			severity = types.SeverityHigh
			break
		}
	}

	for _, ipRange := range types.SuspiciousIPs {
		if strings.HasPrefix(remoteIP.IP, ipRange[:len(ipRange)-3]) {
			severity = types.SeverityMedium
			break
		}
	}

	data := make(map[string]interface{})
	data["protocol"] = conn.Protocol
	data["source_ip"] = localIP.IP
	data["source_port"] = localPort
	data["dest_ip"] = remoteIP.IP
	data["dest_port"] = remotePort
	data["state"] = getTCPState(conn.State)
	data["process_name"] = processName
	data["process_path"] = processPath
	data["pid"] = conn.PID
	data["event_type"] = "new"
	data["is_listening"] = conn.State == 2

	return &types.MonitorEvent{
		ID:        fmt.Sprintf("net-%s-%d-%d", conn.Protocol, localPort, time.Now().UnixNano()),
		Type:      types.EventTypeNetwork,
		Timestamp: time.Now(),
		Severity:  severity,
		Data:      data,
	}
}

func (np *NetworkPoller) createNetworkCloseEvent(conn *types.ConnectionInfo, isTCP bool) *types.MonitorEvent {
	processName, _ := getProcessNameAndPath(conn.PID)

	data := make(map[string]interface{})
	data["protocol"] = conn.Protocol
	data["source_ip"], _ = splitAddr(conn.LocalAddr)
	data["source_port"] = extractPort(conn.LocalAddr)
	data["dest_ip"], _ = splitAddr(conn.RemoteAddr)
	data["dest_port"] = extractPort(conn.RemoteAddr)
	data["process_name"] = processName
	data["pid"] = conn.PID
	data["event_type"] = "close"

	return &types.MonitorEvent{
		ID:        fmt.Sprintf("net-close-%s-%d-%d", conn.Protocol, extractPort(conn.LocalAddr), time.Now().UnixNano()),
		Type:      types.EventTypeNetwork,
		Timestamp: time.Now(),
		Severity:  types.SeverityInfo,
		Data:      data,
	}
}

func (np *NetworkPoller) publishEvent(event *types.MonitorEvent) {
	np.subMu.RLock()
	defer np.subMu.RUnlock()

	for _, ch := range np.subscribers {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Channel was closed, ignore
				}
			}()
			select {
			case ch <- event:
			default:
			}
		}()
	}
}

func splitAddr(addr string) (Addr, uint16) {
	if strings.HasPrefix(addr, "[") {
		endIdx := strings.LastIndex(addr, "]:")
		if endIdx > 0 {
			ip := addr[1:endIdx]
			var port uint16
			fmt.Sscanf(addr[endIdx+2:], "%d", &port)
			return Addr{IP: ip, Port: port}, port
		}
	}

	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		var port uint16
		fmt.Sscanf(parts[1], "%d", &port)
		return Addr{IP: parts[0], Port: port}, port
	}
	return Addr{IP: addr, Port: 0}, 0
}

func getProcessNameAndPath(pid uint32) (string, string) {
	if pid == 0 {
		return "System", ""
	}

	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "Unknown", ""
	}
	defer windows.CloseHandle(hProcess)

	if hProcess == 0 {
		return "Unknown", ""
	}

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(hProcess, 0, &buf[0], &size); err != nil {
		return "Unknown", ""
	}

	path := windows.UTF16ToString(buf[:size])
	if path == "" {
		return "Unknown", ""
	}

	parts := strings.Split(path, "\\")
	name := "Unknown"
	if len(parts) > 0 {
		name = parts[len(parts)-1]
	}

	return name, path
}

func getTCPState(state uint32) string {
	states := map[uint32]string{
		1:  "CLOSED",
		2:  "LISTEN",
		3:  "SYN_SENT",
		4:  "SYN_RCVD",
		5:  "ESTABLISHED",
		6:  "FIN_WAIT_1",
		7:  "FIN_WAIT_2",
		8:  "CLOSE_WAIT",
		9:  "CLOSING",
		10: "LAST_ACK",
		11: "TIME_WAIT",
		12: "DELETE_TCB",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "UNKNOWN"
}
