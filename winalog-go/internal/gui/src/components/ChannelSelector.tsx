import { useState, useEffect } from 'react';
import { ChannelConfig } from '../hooks/useLiveEvents';

interface ChannelSelectorProps {
  channels: ChannelConfig[];
  onChannelsChange: (channels: ChannelConfig[]) => void;
  onSave: () => void;
  saving: boolean;
}

export function ChannelSelector({ channels, onChannelsChange, onSave, saving }: ChannelSelectorProps) {
  const [availableChannels, setAvailableChannels] = useState<string[]>([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newChannel, setNewChannel] = useState({ name: '', description: '', event_ids: '' });

  useEffect(() => {
    fetchAvailableChannels();
  }, []);

  const fetchAvailableChannels = async () => {
    try {
      const response = await fetch('/api/live/channels/available');
      const data = await response.json();
      setAvailableChannels(data.channels || []);
    } catch (error) {
      console.error('Failed to fetch available channels:', error);
    }
  };

  const handleToggle = (index: number) => {
    const newChannels = [...channels];
    newChannels[index] = {
      ...newChannels[index],
      enabled: !newChannels[index].enabled,
    };
    onChannelsChange(newChannels);
  };

  const handleEventIdsChange = (index: number, value: string) => {
    const newChannels = [...channels];
    newChannels[index] = {
      ...newChannels[index],
      event_ids: value,
    };
    onChannelsChange(newChannels);
  };

  const handleAddChannel = () => {
    if (!newChannel.name.trim()) return;

    const exists = channels.some(c => c.name === newChannel.name);
    if (exists) {
      alert('该日志源已存在');
      return;
    }

    const added: ChannelConfig = {
      name: newChannel.name.trim(),
      description: newChannel.description.trim() || newChannel.name,
      event_ids: newChannel.event_ids.trim(),
      enabled: true,
    };

    onChannelsChange([...channels, added]);
    setNewChannel({ name: '', description: '', event_ids: '' });
    setShowAddForm(false);
  };

  const handleRemoveChannel = (name: string) => {
    const newChannels = channels.filter(c => c.name !== name);
    onChannelsChange(newChannels);
  };

  const isSystemChannel = (name: string) => {
    return availableChannels.some(ac => ac.toLowerCase() === name.toLowerCase());
  };

  return (
    <div className="channel-selector" style={{
      background: 'linear-gradient(135deg, #16213e 0%, #1a1a2e 100%)',
      borderRadius: '12px',
      padding: '20px',
      border: '1px solid #333',
      marginBottom: '20px'
    }}>
      <div className="section-header" style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '16px'
      }}>
        <h3 style={{ color: '#00d9ff', margin: 0, fontSize: '1rem' }}>日志源订阅配置</h3>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            style={{
              padding: '8px 16px',
              background: 'rgba(0, 217, 255, 0.1)',
              border: '1px solid #00d9ff',
              borderRadius: '6px',
              color: '#00d9ff',
              cursor: 'pointer',
              fontSize: '14px'
            }}
          >
            {showAddForm ? '取消添加' : '+ 添加日志源'}
          </button>
          <button
            className="btn-primary btn-sm"
            onClick={onSave}
            disabled={saving}
            style={{
              padding: '8px 16px',
              background: saving ? 'rgba(0, 217, 255, 0.3)' : 'rgba(0, 217, 255, 0.1)',
              border: '1px solid #00d9ff',
              borderRadius: '6px',
              color: '#00d9ff',
              cursor: saving ? 'not-allowed' : 'pointer',
              fontSize: '14px'
            }}
          >
            {saving ? '保存中...' : '保存配置'}
          </button>
        </div>
      </div>

      {showAddForm && (
        <div style={{
          background: 'rgba(0, 0, 0, 0.3)',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '16px',
          border: '1px dashed #00d9ff'
        }}>
          <h4 style={{ color: '#00d9ff', margin: '0 0 12px 0', fontSize: '14px' }}>添加自定义日志源</h4>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '12px', alignItems: 'end' }}>
            <div>
              <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '4px' }}>日志源名称 *</label>
              <input
                type="text"
                placeholder="如: Microsoft-Windows-TaskScheduler/Operational"
                value={newChannel.name}
                onChange={(e) => setNewChannel({ ...newChannel, name: e.target.value })}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid #333',
                  borderRadius: '4px',
                  color: '#eee',
                  fontSize: '13px'
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '4px' }}>描述</label>
              <input
                type="text"
                placeholder="如: 任务计划"
                value={newChannel.description}
                onChange={(e) => setNewChannel({ ...newChannel, description: e.target.value })}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid #333',
                  borderRadius: '4px',
                  color: '#eee',
                  fontSize: '13px'
                }}
              />
            </div>
            <div>
              <label style={{ display: 'block', color: '#888', fontSize: '12px', marginBottom: '4px' }}>事件ID (可选)</label>
              <input
                type="text"
                placeholder="如: 100,101,102"
                value={newChannel.event_ids}
                onChange={(e) => setNewChannel({ ...newChannel, event_ids: e.target.value })}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid #333',
                  borderRadius: '4px',
                  color: '#eee',
                  fontSize: '13px'
                }}
              />
            </div>
            <button
              onClick={handleAddChannel}
              disabled={!newChannel.name.trim()}
              style={{
                padding: '8px 16px',
                background: newChannel.name.trim() ? 'rgba(34, 197, 94, 0.1)' : 'rgba(102, 102, 102, 0.1)',
                border: `1px solid ${newChannel.name.trim() ? '#22c55e' : '#666'}`,
                borderRadius: '6px',
                color: newChannel.name.trim() ? '#22c55e' : '#666',
                cursor: newChannel.name.trim() ? 'pointer' : 'not-allowed',
                fontSize: '14px'
              }}
            >
              添加
            </button>
          </div>
          <div style={{ marginTop: '12px' }}>
            <span style={{ color: '#888', fontSize: '12px' }}>系统可用日志源: </span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
              {availableChannels.slice(0, 20).map(ch => (
                <span
                  key={ch}
                  onClick={() => setNewChannel({ ...newChannel, name: ch })}
                  style={{
                    background: 'rgba(0, 0, 0, 0.3)',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    color: '#00d9ff',
                    cursor: 'pointer',
                    border: '1px solid transparent'
                  }}
                  title="点击选择"
                >
                  {ch.length > 40 ? ch.substring(0, 40) + '...' : ch}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {channels.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '20px', color: '#888' }}>
          <div style={{ marginBottom: '12px' }}>暂无配置的日志源，请从下方系统可用日志源中选择或添加自定义日志源</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center', maxWidth: '800px', margin: '0 auto' }}>
            {availableChannels.map(ch => (
              <div
                key={ch}
                onClick={() => {
                  const added: ChannelConfig = {
                    name: ch,
                    description: ch.split('/').pop() || ch,
                    event_ids: '',
                    enabled: true,
                  };
                  onChannelsChange([...channels, added]);
                }}
                style={{
                  background: 'rgba(0, 217, 255, 0.1)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  color: '#00d9ff',
                  cursor: 'pointer',
                  border: '1px solid rgba(0, 217, 255, 0.3)',
                }}
                title="点击添加此日志源"
              >
                {ch.length > 50 ? ch.substring(0, 50) + '...' : ch}
              </div>
            ))}
          </div>
          {availableChannels.length === 0 && (
            <div style={{ marginTop: '12px', color: '#666' }}>
              正在加载可用日志源...
            </div>
          )}
        </div>
      ) : (
        <div className="channel-list" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {channels.map((channel, index) => (
            <div key={channel.name} style={{
              display: 'grid',
              gridTemplateColumns: 'auto 1fr auto auto',
              gap: '12px',
              alignItems: 'center',
              padding: '12px 16px',
              background: channel.enabled ? 'rgba(0, 217, 255, 0.05)' : 'rgba(0, 0, 0, 0.2)',
              borderRadius: '8px',
              border: '1px solid',
              borderColor: channel.enabled ? 'rgba(0, 217, 255, 0.3)' : '#333',
              transition: 'all 0.2s'
            }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={channel.enabled}
                  onChange={() => handleToggle(index)}
                  style={{ width: '18px', height: '18px', accentColor: '#00d9ff' }}
                />
                <div>
                  <span style={{ color: channel.enabled ? '#fff' : '#888', fontWeight: 500, fontSize: '14px' }}>{channel.name}</span>
                  <span style={{ color: '#6b7280', fontSize: '12px', marginLeft: '8px' }}>{channel.description}</span>
                </div>
              </label>
              <input
                type="text"
                className="channel-event-ids"
                placeholder="事件ID (如: 4624,4625)"
                value={channel.event_ids}
                onChange={(e) => handleEventIdsChange(index, e.target.value)}
                disabled={!channel.enabled}
                style={{
                  padding: '6px 10px',
                  background: 'rgba(0, 0, 0, 0.3)',
                  border: '1px solid #333',
                  borderRadius: '4px',
                  color: channel.enabled ? '#eee' : '#666',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                  width: '180px',
                  opacity: channel.enabled ? 1 : 0.5
                }}
              />
              {!isSystemChannel(channel.name) && (
                <span style={{
                  background: 'rgba(245, 158, 11, 0.1)',
                  color: '#f59e0b',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '10px'
                }}>
                  自定义
                </span>
              )}
              <button
                onClick={() => handleRemoveChannel(channel.name)}
                style={{
                  padding: '4px 8px',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid #ef4444',
                  borderRadius: '4px',
                  color: '#ef4444',
                  cursor: 'pointer',
                  fontSize: '12px'
                }}
                title="移除"
              >
                删除
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ChannelSelector;
