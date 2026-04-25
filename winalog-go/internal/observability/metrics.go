package observability

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type MetricsCollector struct {
	mu sync.RWMutex

	registry         *prometheus.Registry
	eventsTotal      prometheus.Counter
	eventsImported   prometheus.Counter
	alertsTotal      prometheus.Counter
	alertsTriggered  prometheus.Counter
	importDuration   prometheus.Histogram
	eventsPerSecond  prometheus.Gauge
	activeCollectors prometheus.Gauge
	rulesLoaded      prometheus.Gauge
	rulesMatched     prometheus.Counter

	startTime time.Time
}

func NewMetricsCollector() *MetricsCollector {
	m := &MetricsCollector{
		startTime: time.Now(),
		registry:  prometheus.NewRegistry(),
	}

	m.eventsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "winalog_events_total",
		Help: "Total number of events in database",
	})

	m.eventsImported = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "winalog_events_imported_total",
		Help: "Total number of events imported",
	})

	m.alertsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "winalog_alerts_total",
		Help: "Total number of alerts generated",
	})

	m.alertsTriggered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "winalog_alerts_triggered_total",
		Help: "Number of alert rule triggers",
	})

	m.importDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "winalog_import_duration_seconds",
		Help:    "Time spent importing files",
		Buckets: prometheus.DefBuckets,
	})

	m.eventsPerSecond = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "winalog_events_per_second",
		Help: "Current event ingestion rate",
	})

	m.activeCollectors = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "winalog_active_collectors",
		Help: "Number of active event collectors",
	})

	m.rulesLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "winalog_rules_loaded",
		Help: "Number of rules loaded",
	})

	m.rulesMatched = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "winalog_rules_matched_total",
		Help: "Number of times rules matched events",
	})

	m.registry.MustRegister(
		m.eventsTotal,
		m.eventsImported,
		m.alertsTotal,
		m.alertsTriggered,
		m.importDuration,
		m.eventsPerSecond,
		m.activeCollectors,
		m.rulesLoaded,
		m.rulesMatched,
	)

	return m
}

func (m *MetricsCollector) Registry() *prometheus.Registry {
	return m.registry
}

func (m *MetricsCollector) RecordEvent() {
	m.eventsTotal.Inc()
}

func (m *MetricsCollector) RecordImport(count int64) {
	m.eventsImported.Add(float64(count))
}

func (m *MetricsCollector) RecordAlert() {
	m.alertsTotal.Inc()
}

func (m *MetricsCollector) RecordAlertTrigger() {
	m.alertsTriggered.Inc()
}

func (m *MetricsCollector) RecordRuleMatch() {
	m.rulesMatched.Inc()
}

func (m *MetricsCollector) SetRulesLoaded(count int) {
	m.rulesLoaded.Set(float64(count))
}

func (m *MetricsCollector) SetEventsPerSecond(rate float64) {
	m.eventsPerSecond.Set(rate)
}

func (m *MetricsCollector) SetActiveCollectors(count int) {
	m.activeCollectors.Set(float64(count))
}

func (m *MetricsCollector) ObserveImportDuration(d time.Duration) {
	m.importDuration.Observe(d.Seconds())
}

func (m *MetricsCollector) GetUptime() time.Duration {
	return time.Since(m.startTime)
}

func (m *MetricsCollector) String() string {
	uptime := m.GetUptime()
	return fmt.Sprintf(`# HELP winalog_uptime_seconds Application uptime in seconds
# TYPE winalog_uptime_seconds gauge
winalog_uptime_seconds %f

# HELP winalog_events_per_second Current event ingestion rate
# TYPE winalog_events_per_second gauge
winalog_events_per_second %f

# HELP winalog_active_collectors Number of active collectors
# TYPE winalog_active_collectors gauge
winalog_active_collectors %f
`,
		uptime.Seconds(),
		0.0,
		0.0,
	)
}
