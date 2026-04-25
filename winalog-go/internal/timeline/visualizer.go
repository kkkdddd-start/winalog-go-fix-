package timeline

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

type TimelineVisualizer struct {
	timeline *Timeline
	config   *VisualizerConfig
}

type VisualizerConfig struct {
	Width           int
	Height          int
	TimeWindow      time.Duration
	ZoomLevel       float64
	ShowMITRELabels bool
	ShowThumbnails  bool
	Theme           string
}

type VisualizerOutput struct {
	HTML    string
	JSON    string
	Summary VisualizerSummary
}

type VisualizerSummary struct {
	TotalEntries   int            `json:"total_entries"`
	ByCategory     map[string]int `json:"by_category"`
	ByLevel        map[string]int `json:"by_level"`
	AttackChains   int            `json:"attack_chains"`
	TimeRangeHours float64        `json:"time_range_hours"`
	ZoomLevel      float64        `json:"zoom_level"`
}

const DefaultVisualizerConfig = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WinLogAnalyzer Timeline</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #1a1a2e; color: #eee; }
        .timeline-container { position: relative; padding: 20px 0; }
        .timeline-axis { 
            position: absolute; 
            left: 0; 
            right: 0; 
            height: 40px; 
            background: #16213e;
            border-radius: 4px;
        }
        .timeline-entry {
            position: absolute;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .timeline-entry:hover { transform: scale(1.5); }
        .level-critical { background-color: #e74c3c; }
        .level-error { background-color: #e67e22; }
        .level-warning { background-color: #f1c40f; }
        .level-info { background-color: #3498db; }
        .level-verbose { background-color: #95a5a6; }
        .tooltip-content { 
            background: #2c3e50; 
            padding: 10px; 
            border-radius: 4px;
            max-width: 400px;
        }
        .category-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            margin-right: 5px;
        }
        .cat-authentication { background-color: #9b59b6; }
        .cat-process { background-color: #e74c3c; }
        .cat-network { background-color: #3498db; }
        .cat-registry { background-color: #2ecc71; }
        .cat-unknown { background-color: #7f8c8d; }
        .attack-chain-line {
            position: absolute;
            left: 0;
            right: 0;
            height: 3px;
            background: rgba(231, 76, 60, 0.6);
            z-index: -1;
        }
        .controls {
            background: #16213e;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .mitre-tag {
            background: #e74c3c;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
            margin-left: 5px;
        }
        #timeline-canvas { width: 100%; height: 300px; }
        .event-detail {
            background: #16213e;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container-fluid p-4">
        <h4 class="mb-4">WinLogAnalyzer Timeline</h4>
        
        <div class="controls">
            <div class="row">
                <div class="col-md-3">
                    <label>Zoom Level</label>
                    <input type="range" class="form-range" id="zoom" min="1" max="10" value="5">
                </div>
                <div class="col-md-3">
                    <label>Time Window</label>
                    <select class="form-select" id="time-window">
                        <option value="1h">1 Hour</option>
                        <option value="6h">6 Hours</option>
                        <option value="24h" selected>24 Hours</option>
                        <option value="7d">7 Days</option>
                        <option value="30d">30 Days</option>
                        <option value="custom">Custom Range</option>
                    </select>
                </div>
                <div class="col-md-3" id="custom-time-range" style="display: none;">
                    <label>Start Time</label>
                    <input type="datetime-local" class="form-control" id="time-start" step="1">
                </div>
                <div class="col-md-3" id="custom-time-end" style="display: none;">
                    <label>End Time</label>
                    <input type="datetime-local" class="form-control" id="time-end" step="1">
                </div>
                <div class="col-md-3">
                    <label>Category Filter</label>
                    <select class="form-select" id="category-filter">
                        <option value="">All Categories</option>
                        <option value="Authentication">Authentication</option>
                        <option value="Process">Process</option>
                        <option value="Network">Network</option>
                        <option value="Registry">Registry</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label>Show MITRE</label>
                    <input type="checkbox" id="show-mitre" checked>
                </div>
            </div>
        </div>

        <div class="timeline-container" id="timeline-container">
            <canvas id="timeline-canvas"></canvas>
        </div>

        <div class="row mt-3">
            <div class="col-md-4">
                <div class="card bg-dark text-white">
                    <div class="card-header">Statistics</div>
                    <div class="card-body">
                        <p>Total Events: <span id="stat-total">{{.Summary.TotalEntries}}</span></p>
                        <p>Time Range: <span id="stat-range">{{printf "%.1f" .Summary.TimeRangeHours}}</span> hours</p>
                        <p>Attack Chains: <span id="stat-chains">{{.Summary.AttackChains}}</span></p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card bg-dark text-white">
                    <div class="card-header">By Level</div>
                    <div class="card-body" id="level-stats">
                        <!-- Level statistics will be populated here -->
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card bg-dark text-white">
                    <div class="card-header">By Category</div>
                    <div class="card-body" id="category-stats">
                        <!-- Category statistics will be populated here -->
                    </div>
                </div>
            </div>
        </div>

        <div class="event-detail" id="event-detail" style="display: none;">
            <h5>Event Details</h5>
            <div id="event-content"></div>
        </div>
    </div>

    <script>
        const timelineData = {{.JSON}};
        //# sourceURL=timeline.js

        function initTimeline() {
            const canvas = document.getElementById('timeline-canvas');
            const ctx = canvas.getContext('2d');
            
            canvas.width = canvas.offsetWidth;
            canvas.height = canvas.offsetHeight;

            drawTimeline(ctx, timelineData.entries);
            populateStats();
        }

        function drawTimeline(ctx, entries) {
            const startTime = entries[0] ? new Date(entries[0].timestamp) : new Date();
            const endTime = entries[entries.length - 1] ? new Date(entries[entries.length-1].timestamp) : new Date();
            const timeRange = endTime - startTime;

            entries.forEach((entry, i) => {
                const entryTime = new Date(entry.timestamp);
                const x = ((entryTime - startTime) / timeRange) * canvas.width;
                const y = 50 + (i % 5) * 30;

                ctx.beginPath();
                ctx.arc(x, y, 6, 0, Math.PI * 2);
                ctx.fillStyle = getLevelColor(entry.level);
                ctx.fill();

                ctx.fillStyle = '#fff';
                ctx.font = '10px Arial';
                ctx.fillText(entry.event_id, x + 10, y + 4);
            });
        }

        function getLevelColor(level) {
            const colors = {
                'Critical': '#e74c3c',
                'Error': '#e67e22',
                'Warning': '#f1c40f',
                'Info': '#3498db',
                'Verbose': '#95a5a6'
            };
            return colors[level] || '#7f8c8d';
        }

        function populateStats() {
            const levelDiv = document.getElementById('level-stats');
            const categoryDiv = document.getElementById('category-stats');

            const byLevel = JSON.parse({{.ByLevel}});
            Object.entries(byLevel).forEach(([level, count]) => {
                levelDiv.innerHTML += '<p>' + level + ': ' + count + '</p>';
            });

            const byCategory = JSON.parse({{.ByCategory}});
            Object.entries(byCategory).forEach(([category, count]) => {
                categoryDiv.innerHTML += '<p>' + category + ': ' + count + '</p>';
            });
        }

        document.addEventListener('DOMContentLoaded', initTimeline);
    </script>
</body>
</html>`

func NewTimelineVisualizer(timeline *Timeline) *TimelineVisualizer {
	return &TimelineVisualizer{
		timeline: timeline,
		config: &VisualizerConfig{
			Width:           1200,
			Height:          400,
			TimeWindow:      24 * time.Hour,
			ZoomLevel:       1.0,
			ShowMITRELabels: true,
			ShowThumbnails:  false,
			Theme:           "dark",
		},
	}
}

func (v *TimelineVisualizer) SetConfig(config *VisualizerConfig) {
	if config != nil {
		v.config = config
	}
}

func (v *TimelineVisualizer) RenderHTML(w io.Writer) error {
	tmpl, err := template.New("timeline").Parse(DefaultVisualizerConfig)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	output := v.GenerateOutput()

	byLevelJSON, _ := json.Marshal(output.Summary.ByLevel)
	byCategoryJSON, _ := json.Marshal(output.Summary.ByCategory)

	escapedJSON := strings.ReplaceAll(output.JSON, "</", "\\u003c/")
	escapedJSON = strings.ReplaceAll(escapedJSON, "<", "\\u003c")

	data := struct {
		JSON          template.HTML
		ByLevel       template.HTML
		ByCategory    template.HTML
		Summary       VisualizerSummary
	}{
		JSON:          template.HTML(escapedJSON),
		ByLevel:       template.HTML(byLevelJSON),
		ByCategory:    template.HTML(byCategoryJSON),
		Summary:       output.Summary,
	}

	return tmpl.Execute(w, data)
}

func (v *TimelineVisualizer) RenderJSON() (string, error) {
	output := v.GenerateOutput()
	return output.JSON, nil
}

func (v *TimelineVisualizer) GenerateOutput() *VisualizerOutput {
	output := &VisualizerOutput{
		Summary: VisualizerSummary{
			TotalEntries:   v.timeline.TotalCount,
			ByCategory:     make(map[string]int),
			ByLevel:        make(map[string]int),
			AttackChains:   0,
			TimeRangeHours: v.timeline.Duration.Hours(),
			ZoomLevel:      v.config.ZoomLevel,
		},
	}

	for _, entry := range v.timeline.Entries {
		output.Summary.ByCategory[entry.Category]++
		output.Summary.ByLevel[entry.Level]++
		if entry.AttackChain != "" {
			output.Summary.AttackChains++
		}
	}

	jsonData, _ := json.Marshal(v.timeline)
	output.JSON = string(jsonData)

	return output
}

func (v *TimelineVisualizer) GetSummary() *VisualizerSummary {
	summary := &VisualizerSummary{
		TotalEntries:   v.timeline.TotalCount,
		ByCategory:     make(map[string]int),
		ByLevel:        make(map[string]int),
		AttackChains:   0,
		TimeRangeHours: v.timeline.Duration.Hours(),
		ZoomLevel:      v.config.ZoomLevel,
	}

	for _, entry := range v.timeline.Entries {
		summary.ByCategory[entry.Category]++
		summary.ByLevel[entry.Level]++
		if entry.AttackChain != "" {
			summary.AttackChains++
		}
	}

	return summary
}

func (v *TimelineVisualizer) FilterByTimeRange(start, end time.Time) *TimelineVisualizer {
	filtered := make([]*TimelineEntry, 0)
	for _, entry := range v.timeline.Entries {
		if entry.Timestamp.After(start) && entry.Timestamp.Before(end) {
			filtered = append(filtered, entry)
		}
	}

	newTimeline := &Timeline{
		Entries:    filtered,
		TotalCount: len(filtered),
		StartTime:  start,
		EndTime:    end,
		Duration:   end.Sub(start),
	}

	return NewTimelineVisualizer(newTimeline)
}

func (v *TimelineVisualizer) FilterByCategory(category string) *TimelineVisualizer {
	filtered := make([]*TimelineEntry, 0)
	for _, entry := range v.timeline.Entries {
		if entry.Category == category {
			filtered = append(filtered, entry)
		}
	}

	newTimeline := &Timeline{
		Entries:    filtered,
		TotalCount: len(filtered),
		StartTime:  v.timeline.StartTime,
		EndTime:    v.timeline.EndTime,
		Duration:   v.timeline.Duration,
	}

	return NewTimelineVisualizer(newTimeline)
}

func (v *TimelineVisualizer) FilterByLevel(level string) *TimelineVisualizer {
	filtered := make([]*TimelineEntry, 0)
	for _, entry := range v.timeline.Entries {
		if entry.Level == level {
			filtered = append(filtered, entry)
		}
	}

	newTimeline := &Timeline{
		Entries:    filtered,
		TotalCount: len(filtered),
		StartTime:  v.timeline.StartTime,
		EndTime:    v.timeline.EndTime,
		Duration:   v.timeline.Duration,
	}

	return NewTimelineVisualizer(newTimeline)
}

func (v *TimelineVisualizer) Zoom(factor float64) *TimelineVisualizer {
	v.config.ZoomLevel *= factor
	return v
}

type TimelineExportFormat string

const (
	FormatTimelineHTML TimelineExportFormat = "html"
	FormatTimelineJSON TimelineExportFormat = "json"
	FormatTimelineCSV  TimelineExportFormat = "csv"
)

func (v *TimelineVisualizer) Export(format TimelineExportFormat, w io.Writer) error {
	switch format {
	case FormatTimelineHTML:
		return v.RenderHTML(w)
	case FormatTimelineJSON:
		jsonData, err := v.RenderJSON()
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(jsonData))
		return err
	case FormatTimelineCSV:
		return v.exportCSV(w)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func (v *TimelineVisualizer) exportCSV(w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"ID", "Timestamp", "EventID", "Level", "Category", "Source", "LogName", "Computer", "User", "Message"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, entry := range v.timeline.Entries {
		record := []string{
			fmt.Sprintf("%d", entry.ID),
			entry.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%d", entry.EventID),
			entry.Level,
			entry.Category,
			entry.Source,
			entry.LogName,
			entry.Computer,
			entry.User,
			entry.Message,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}
