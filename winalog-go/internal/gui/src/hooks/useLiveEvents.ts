import { useEffect, useRef, useState, useCallback } from 'react';

export interface LiveEvent {
  id: number;
  timestamp: string;
  level: number;
  level_name: string;
  source: string;
  log_name: string;
  computer: string;
  user?: string;
  message: string;
  event_id: number;
  provider_name?: string;
}

export interface EventFilters {
  eventId?: string;
  level?: string;
  startTime?: string;
  endTime?: string;
  keyword?: string;
  channel?: string;
}

export interface UseLiveEventsOptions {
  channels?: string[];
  query?: string;
  maxEvents?: number;
  pollInterval?: number;
  filters?: EventFilters;
  onError?: (error: string) => void;
  onConnected?: () => void;
  onDisconnected?: () => void;
}

interface LiveEventsResponse {
  events: LiveEvent[];
  since_id: number;
  next_id: number;
  total: number;
  timestamp: string;
}

export interface ChannelConfig {
  name: string;
  description: string;
  event_ids: string;
  enabled: boolean;
}

interface ChannelsResponse {
  channels: ChannelConfig[];
}

export interface UseLiveEventsOptions {
  channels?: string[];
  query?: string;
  maxEvents?: number;
  pollInterval?: number;
  filters?: EventFilters;
  onError?: (error: string) => void;
  onConnected?: () => void;
  onDisconnected?: () => void;
}

interface LiveEventsResponse {
  events: LiveEvent[];
  since_id: number;
  next_id: number;
  total: number;
  timestamp: string;
}

const LIVE_ENABLED_KEY = 'winalog_live_enabled';

const API_BASE = '/api/live';

export function useLiveEvents(options: UseLiveEventsOptions = {}) {
  const {
    maxEvents = 100,
    pollInterval = 2000,
    filters: initialFilters = {},
    onError,
    onConnected,
    onDisconnected,
  } = options;

  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [stats, setStats] = useState({ total: 0, bufferSize: 0, isCollecting: false });
  const [filters, setFilters] = useState<EventFilters>(initialFilters);

  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const sinceIDRef = useRef(0);
  const reconnectAttempts = useRef(0);
  const isFetchingRef = useRef(false);
  const isVisibleRef = useRef(true);

  useEffect(() => {
    const handleVisibilityChange = () => {
      isVisibleRef.current = document.visibilityState === 'visible';
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  const buildQueryString = (extraFilters: EventFilters = {}) => {
    const params = new URLSearchParams();
    params.set('since_id', sinceIDRef.current.toString());
    params.set('limit', maxEvents.toString());

    const mergedFilters = { ...filters, ...extraFilters };

    if (mergedFilters.channel) params.set('channel', mergedFilters.channel);
    if (mergedFilters.eventId) params.set('event_id', mergedFilters.eventId);
    if (mergedFilters.level) params.set('level', mergedFilters.level);
    if (mergedFilters.startTime) params.set('start_time', mergedFilters.startTime);
    if (mergedFilters.endTime) params.set('end_time', mergedFilters.endTime);
    if (mergedFilters.keyword) params.set('keyword', mergedFilters.keyword);

    return params.toString();
  };

  const fetchEvents = useCallback(async (extraFilters?: EventFilters) => {
    if (isFetchingRef.current || !isVisibleRef.current) return;
    isFetchingRef.current = true;

    try {
      const queryString = buildQueryString(extraFilters);
      const response = await fetch(`${API_BASE}/events?${queryString}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data: LiveEventsResponse = await response.json();

      if (data.events && data.events.length > 0) {
        setEvents(prev => {
          const newEvents = [...data.events, ...prev];
          return newEvents.slice(0, maxEvents);
        });

        const maxID = Math.max(...data.events.map(e => e.id));
        if (maxID > sinceIDRef.current) {
          sinceIDRef.current = maxID;
        }
      }

      if (!isConnected) {
        setIsConnected(true);
        setIsConnecting(false);
        reconnectAttempts.current = 0;
        onConnected?.();
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      console.error('Failed to fetch events:', errorMsg);
      onError?.(errorMsg);

      setIsConnected(false);
      onDisconnected?.();
    } finally {
      isFetchingRef.current = false;
    }
  }, [maxEvents, onConnected, onDisconnected, onError, filters]);

  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/monitoring-stats`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setStats({
        total: data.total_events || 0,
        bufferSize: data.buffer_size || 0,
        isCollecting: data.is_collecting || false,
      });
    } catch {
    }
  }, []);

  const fetchChannels = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/channels`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data: ChannelsResponse = await response.json();
      return data.channels;
    } catch {
      return [];
    }
  }, []);

  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return;

    setIsConnecting(true);
    fetchEvents();
    fetchStats();

    pollIntervalRef.current = setInterval(() => {
      fetchEvents();
      fetchStats();
    }, pollInterval);
  }, [pollInterval, fetchEvents, fetchStats]);

  const stopPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    setIsConnected(false);
    setIsConnecting(false);
  }, []);

  useEffect(() => {
    if (enabled) {
      startPolling();
    } else {
      stopPolling();
    }

    return () => {
      stopPolling();
    };
  }, [enabled, startPolling, stopPolling]);

  const handleSetEnabled = useCallback((value: boolean) => {
    localStorage.setItem(LIVE_ENABLED_KEY, String(value));
    setEnabled(value);
    if (!value) {
      stopPolling();
    }
  }, [stopPolling]);

  const clearEvents = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/events`, {
        method: 'DELETE',
      });
      if (response.ok) {
        setEvents([]);
        sinceIDRef.current = 0;
      }
    } catch (err) {
      console.error('Failed to clear events:', err);
    }
  }, []);

  const updateChannels = useCallback(async (newChannels: ChannelConfig[]) => {
    try {
      const response = await fetch(`${API_BASE}/channels`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ channels: newChannels }),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return true;
    } catch (err) {
      console.error('Failed to update channels:', err);
      return false;
    }
  }, []);

  const applyFilters = useCallback((newFilters: EventFilters) => {
    setFilters(newFilters);
    sinceIDRef.current = 0;
    setEvents([]);
    fetchEvents(newFilters);
  }, [fetchEvents]);

  const clearFilters = useCallback(() => {
    setFilters({});
    sinceIDRef.current = 0;
    setEvents([]);
    fetchEvents({});
  }, [fetchEvents]);

  return {
    events,
    isConnected,
    isConnecting,
    enabled,
    setEnabled: handleSetEnabled,
    clearEvents,
    stats,
    filters,
    fetchChannels,
    updateChannels,
    applyFilters,
    clearFilters,
  };
}
