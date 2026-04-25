package multi

import (
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type MultiMachineAnalyzer struct {
	db       *storage.DB
	machines map[string]*MultiMachineContext
	mu       sync.RWMutex
}

type MultiMachineContext struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	IP        string         `json:"ip"`
	Role      string         `json:"role"`
	Events    []*types.Event `json:"events"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
}

type LateralMovement struct {
	SourceMachine string         `json:"source_machine"`
	TargetMachine string         `json:"target_machine"`
	User          string         `json:"user"`
	Technique     string         `json:"technique"`
	Time          time.Time      `json:"time"`
	Evidence      []*types.Event `json:"evidence"`
}

type UserLogin struct {
	Machine string
	User    string
	Time    time.Time
	Event   *types.Event
}

type CrossMachineResult struct {
	Machine         *MultiMachineContext `json:"machine"`
	LateralMovement []*LateralMovement   `json:"lateral_movement"`
	Statistics      *MachineStats        `json:"statistics"`
}

type MachineStats struct {
	TotalEvents      int64            `json:"total_events"`
	EventByLevel     map[string]int64 `json:"event_by_level"`
	TopEventIDs      map[int32]int64  `json:"top_event_ids"`
	LoginAttempts    int64            `json:"login_attempts"`
	FailedLogins     int64            `json:"failed_logins"`
	SuccessfulLogins int64            `json:"successful_logins"`
}

func NewMultiMachineAnalyzer(db *storage.DB) *MultiMachineAnalyzer {
	return &MultiMachineAnalyzer{
		db:       db,
		machines: make(map[string]*MultiMachineContext),
	}
}

func (a *MultiMachineAnalyzer) AddMachine(ctx *MultiMachineContext) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.machines[ctx.ID] = ctx
}

func (a *MultiMachineAnalyzer) GetMachine(id string) (*MultiMachineContext, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ctx, ok := a.machines[id]
	return ctx, ok
}

func (a *MultiMachineAnalyzer) ListMachines() []*MultiMachineContext {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*MultiMachineContext, 0, len(a.machines))
	for _, ctx := range a.machines {
		result = append(result, ctx)
	}
	return result
}

func (a *MultiMachineAnalyzer) Analyze() (*CrossMachineResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := &CrossMachineResult{
		LateralMovement: make([]*LateralMovement, 0),
		Statistics:      &MachineStats{},
	}

	crossMachineMovements := a.detectCrossMachineLateralMovement()
	result.LateralMovement = append(result.LateralMovement, crossMachineMovements...)

	for _, machine := range a.machines {
		if result.Machine == nil {
			result.Machine = machine
		}

		movements := a.detectLateralMovement(machine)
		result.LateralMovement = append(result.LateralMovement, movements...)

		stats := a.calculateStats(machine.Events)
		if result.Statistics.TotalEvents == 0 {
			result.Statistics = stats
		}
	}

	return result, nil
}

func (a *MultiMachineAnalyzer) detectCrossMachineLateralMovement() []*LateralMovement {
	movements := make([]*LateralMovement, 0)

	userLogins := make(map[string][]*UserLogin)
	for _, machine := range a.machines {
		for _, event := range machine.Events {
			if event.EventID == 4624 {
				user := extractUser(event)
				if user != "Unknown" {
					userLogins[user] = append(userLogins[user], &UserLogin{
						Machine: machine.Name,
						User:    user,
						Time:    event.Timestamp,
						Event:   event,
					})
				}
			}
		}
	}

	for user, logins := range userLogins {
		if len(logins) < 2 {
			continue
		}

		machineSet := make(map[string]bool)
		for _, login := range logins {
			machineSet[login.Machine] = true
		}

		if len(machineSet) >= 2 {
			var events []*types.Event
			var lastTime time.Time
			for _, login := range logins {
				events = append(events, login.Event)
				if login.Time.After(lastTime) {
					lastTime = login.Time
				}
			}
			movements = append(movements, &LateralMovement{
				SourceMachine: logins[0].Machine,
				TargetMachine: logins[len(logins)-1].Machine,
				User:          user,
				Technique:     "T1021",
				Time:          lastTime,
				Evidence:      events,
			})
		}
	}

	return movements
}

func (a *MultiMachineAnalyzer) detectLateralMovement(machine *MultiMachineContext) []*LateralMovement {
	movements := make([]*LateralMovement, 0)

	var prevEvent *types.Event
	for _, event := range machine.Events {
		if event.EventID == 4624 {
			if prevEvent != nil && prevEvent.EventID == 4625 {
				movements = append(movements, &LateralMovement{
					SourceMachine: machine.Name,
					TargetMachine: machine.Name,
					User:          extractUser(event),
					Technique:     "Credential Dumping",
					Time:          event.Timestamp,
					Evidence:      []*types.Event{prevEvent, event},
				})
			}
		}
		prevEvent = event
	}

	return movements
}

func (a *MultiMachineAnalyzer) calculateStats(events []*types.Event) *MachineStats {
	stats := &MachineStats{
		EventByLevel: make(map[string]int64),
		TopEventIDs:  make(map[int32]int64),
	}

	for _, event := range events {
		stats.TotalEvents++
		stats.EventByLevel[event.Level.String()]++

		stats.TopEventIDs[event.EventID]++

		switch event.EventID {
		case 4624:
			stats.SuccessfulLogins++
			stats.LoginAttempts++
		case 4625:
			stats.FailedLogins++
			stats.LoginAttempts++
		}
	}

	return stats
}

func extractUser(event *types.Event) string {
	if event.User != nil {
		return *event.User
	}
	return "Unknown"
}

func (a *MultiMachineAnalyzer) DetectDC() []*MultiMachineContext {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var dcs []*MultiMachineContext
	for _, machine := range a.machines {
		if machine.Role == "DC" {
			dcs = append(dcs, machine)
		}
	}
	return dcs
}

func (a *MultiMachineAnalyzer) DetectServers() []*MultiMachineContext {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var servers []*MultiMachineContext
	for _, machine := range a.machines {
		if machine.Role == "Server" {
			servers = append(servers, machine)
		}
	}
	return servers
}

func (a *MultiMachineAnalyzer) DetectWorkstations() []*MultiMachineContext {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var workstations []*MultiMachineContext
	for _, machine := range a.machines {
		if machine.Role == "Workstation" {
			workstations = append(workstations, machine)
		}
	}
	return workstations
}
