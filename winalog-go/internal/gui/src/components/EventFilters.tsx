import { useState } from 'react';

export interface EventFilters {
  eventId?: string;
  level?: string;
  startTime?: string;
  endTime?: string;
  keyword?: string;
  channel?: string;
}

interface EventFiltersProps {
  filters: EventFilters;
  onFiltersChange: (filters: EventFilters) => void;
  onApply: (filters: EventFilters) => void;
  onClear: () => void;
}

export function EventFilters({ filters, onFiltersChange, onApply, onClear }: EventFiltersProps) {
  const [localFilters, setLocalFilters] = useState<EventFilters>(filters);

  const handleChange = (key: keyof EventFilters, value: string) => {
    const newFilters = { ...localFilters, [key]: value || undefined };
    setLocalFilters(newFilters);
    onFiltersChange(newFilters);
  };

  const handleClear = () => {
    const emptyFilters: EventFilters = {};
    setLocalFilters(emptyFilters);
    onFiltersChange(emptyFilters);
    onClear();
  };

  const channels = ['Security', 'System', 'Application', 'Setup', 'ForwardedEvents'];

  const levelOptions = [
    { value: 'Critical', label: '严重' },
    { value: 'Error', label: '错误' },
    { value: 'Warning', label: '警告' },
    { value: 'Info', label: '信息' },
    { value: 'Verbose', label: '详细' },
  ];

  return (
    <div className="event-filters" style={{
      background: 'linear-gradient(135deg, #16213e 0%, #1a1a2e 100%)',
      borderRadius: '12px',
      padding: '20px',
      border: '1px solid #333',
      marginBottom: '20px'
    }}>
      <div className="section-header" style={{
        marginBottom: '16px'
      }}>
        <h3 style={{ color: '#00d9ff', margin: 0, fontSize: '1rem' }}>事件过滤</h3>
      </div>
      <div className="filters-grid" style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '16px',
        marginBottom: '16px'
      }}>
        <div className="filter-group">
          <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>日志源</label>
          <select
            value={localFilters.channel || ''}
            onChange={(e) => handleChange('channel', e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid #333',
              borderRadius: '6px',
              color: '#eee',
              fontSize: '14px'
            }}
          >
            <option value="">全部</option>
            {channels.map((ch) => (
              <option key={ch} value={ch}>{ch}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>事件ID</label>
          <input
            type="text"
            placeholder="如: 4624,4625"
            value={localFilters.eventId || ''}
            onChange={(e) => handleChange('eventId', e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid #333',
              borderRadius: '6px',
              color: '#eee',
              fontSize: '14px'
            }}
          />
        </div>

        <div className="filter-group">
          <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>级别</label>
          <select
            value={localFilters.level || ''}
            onChange={(e) => handleChange('level', e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid #333',
              borderRadius: '6px',
              color: '#eee',
              fontSize: '14px'
            }}
          >
            <option value="">全部</option>
            {levelOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div className="filter-group">
          <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>开始时间</label>
          <input
            type="datetime-local"
            value={localFilters.startTime || ''}
            onChange={(e) => handleChange('startTime', e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid #333',
              borderRadius: '6px',
              color: '#eee',
              fontSize: '14px'
            }}
          />
        </div>

        <div className="filter-group">
          <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>结束时间</label>
          <input
            type="datetime-local"
            value={localFilters.endTime || ''}
            onChange={(e) => handleChange('endTime', e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid #333',
              borderRadius: '6px',
              color: '#eee',
              fontSize: '14px'
            }}
          />
        </div>

        <div className="filter-group filter-keyword">
          <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '6px', textTransform: 'uppercase' }}>关键字</label>
          <input
            type="text"
            placeholder="搜索消息内容"
            value={localFilters.keyword || ''}
            onChange={(e) => handleChange('keyword', e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px',
              background: 'rgba(0, 0, 0, 0.3)',
              border: '1px solid #333',
              borderRadius: '6px',
              color: '#eee',
              fontSize: '14px'
            }}
          />
        </div>
      </div>

      <div className="filter-actions" style={{ display: 'flex', gap: '12px' }}>
        <button
          className="btn-primary"
          onClick={() => onApply(localFilters)}
          style={{
            padding: '10px 20px',
            background: 'rgba(0, 217, 255, 0.1)',
            border: '1px solid #00d9ff',
            borderRadius: '6px',
            color: '#00d9ff',
            cursor: 'pointer',
            fontSize: '14px',
            fontWeight: 500
          }}
        >
          应用过滤
        </button>
        <button
          className="btn-secondary"
          onClick={handleClear}
          style={{
            padding: '10px 20px',
            background: 'transparent',
            border: '1px solid #333',
            borderRadius: '6px',
            color: '#888',
            cursor: 'pointer',
            fontSize: '14px'
          }}
        >
          清除过滤
        </button>
      </div>
    </div>
  );
}

export default EventFilters;
