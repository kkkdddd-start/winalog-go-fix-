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

const LIVE_ENABLED_KEY = 'winalog_live_enabled';

const API_BASE = '/api/live';

type LiveState = 'idle' | 'starting' | 'running' | 'stopping';

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
  const [liveState, setLiveState] = useState<LiveState>('idle');
  const [enabled, setEnabledState] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem(LIVE_ENABLED_KEY) === 'true';
    }
    return false;
  });
  const [stats, setStats] = useState({ total: 0, bufferSize: 0, isCollecting: false });
  const [filters, setFilters] = useState<EventFilters>(initialFilters);

  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const sinceIDRef = useRef(0);
  const isFetchingEventsRef = useRef(false);
  const isFetchingStatsRef = useRef(false);
  const isVisibleRef = useRef(true);

  const requestSeqRef = useRef(0);
  const abortControllerRef = useRef<AbortController | null>(null);
  const isUnmountingRef = useRef(false);

  const pendingActionRef = useRef<'start' | 'stop' | null>(null);
  const actionLockRef = useRef(false);

  const fetchEventsRef = useRef<((extraFilters?: EventFilters) => Promise<void>) | null>(null);
  const fetchStatsRef = useRef<(() => Promise<void>) | null>(null);

  useEffect(() => {
    const handleVisibilityChange = () => {
      isVisibleRef.current = document.visibilityState === 'visible';
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  const buildQueryString = useCallback((extraFilters: EventFilters = {}) => {
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
  }, [maxEvents, filters]);

  const fetchEvents = useCallback(async (extraFilters?: EventFilters) => {
    if (isFetchingEventsRef.current || !isVisibleRef.current) return;
    if (liveState !== 'running') return;

    isFetchingEventsRef.current = true;
    const currentSeq = requestSeqRef.current;

    try {
      abortControllerRef.current?.abort();
      abortControllerRef.current = new AbortController();

      const queryString = buildQueryString(extraFilters);
      const response = await fetch(`${API_BASE}/events?${queryString}`, {
        signal: abortControllerRef.current.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data: LiveEventsResponse = await response.json();

      if (currentSeq !== requestSeqRef.current) {
        console.log('[useLiveEvents] Stale response discarded, seq:', currentSeq);
        return;
      }

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
        onConnected?.();
      }
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        console.log('[useLiveEvents] Request aborted');
        return;
      }
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      console.error('[useLiveEvents] Failed to fetch events:', errorMsg);
      onError?.(errorMsg);

      setIsConnected(false);
      onDisconnected?.();
    } finally {
      isFetchingEventsRef.current = false;
    }
  }, [maxEvents, buildQueryString, isConnected, liveState, onConnected, onDisconnected, onError]);

  const fetchStats = useCallback(async () => {
    if (isFetchingStatsRef.current) return;
    if (liveState !== 'running') return;

    isFetchingStatsRef.current = true;
    const currentSeq = requestSeqRef.current;

    try {
      const response = await fetch(`${API_BASE}/monitoring-stats`);

      if (currentSeq !== requestSeqRef.current) {
        return;
      }

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
    } finally {
      isFetchingStatsRef.current = false;
    }
  }, [liveState]);

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

  const stopPolling = useCallback(async () => {
    console.log('[useLiveEvents] Stopping polling, state:', liveState);

    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }

    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }

    if (liveState === 'idle') {
      console.log('[useLiveEvents] Already idle');
      pendingActionRef.current = null;
      return;
    }

    if (liveState === 'stopping') {
      console.log('[useLiveEvents] Already stopping');
      return;
    }

    pendingActionRef.current = 'stop';
    setLiveState('stopping');

    try {
      await fetch(`${API_BASE}/stop`, { method: 'POST' });
      console.log('[useLiveEvents] Backend stop request sent');
    } catch (err) {
      console.error('[useLiveEvents] Error stopping monitoring:', err);
    }

    setIsConnected(false);
    setIsConnecting(false);
    setLiveState('idle');
    pendingActionRef.current = null;
  }, [liveState]);

  const startPolling = useCallback(async () => {
    console.log('[useLiveEvents] Starting polling, state:', liveState);

    if (liveState === 'running') {
      console.log('[useLiveEvents] Already running');
      return;
    }

    if (liveState === 'starting') {
      console.log('[useLiveEvents] Already starting');
      return;
    }

    if (pendingActionRef.current === 'stop') {
      console.log('[useLiveEvents] Pending stop in progress, skip start');
      return;
    }

    pendingActionRef.current = 'start';
    setLiveState('starting');
    setIsConnecting(true);

    try {
      const response = await fetch(`${API_BASE}/start`, { method: 'POST' });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      console.log('[useLiveEvents] Backend start request sent');
    } catch (err) {
      console.error('[useLiveEvents] Error starting monitoring:', err);
      setLiveState('idle');
      setIsConnecting(false);
      pendingActionRef.current = null;
      return;
    }

    setLiveState('running');
    console.log('[useLiveEvents] Polling started successfully');
    pendingActionRef.current = null;

    fetchEvents();
    fetchStats();

    pollIntervalRef.current = setInterval(() => {
      if (isUnmountingRef.current) return;
      fetchEvents();
      fetchStats();
    }, pollInterval);
  }, [liveState, pollInterval, fetchEvents, fetchStats]);

  useEffect(() => {
    fetchEventsRef.current = fetchEvents;
    fetchStatsRef.current = fetchStats;
  });

  useEffect(() => {
    isUnmountingRef.current = false;
    return () => {
      isUnmountingRef.current = true;
    };
  }, []);

  useEffect(() => {
    if (actionLockRef.current) {
      console.log('[useLiveEvents] Action locked, skip effect');
      return;
    }

    const targetEnabled = enabled;
    console.log('[useLiveEvents] Effect triggered: enabled=', targetEnabled, 'liveState=', liveState);

    if (targetEnabled && liveState === 'idle') {
      actionLockRef.current = true;
      startPolling().finally(() => {
        actionLockRef.current = false;
      });
    } else if (!targetEnabled && liveState === 'running') {
      actionLockRef.current = true;
      stopPolling().finally(() => {
        actionLockRef.current = false;
      });
    }
  }, [enabled, liveState, startPolling, stopPolling]);

  const handleSetEnabled = useCallback((value: boolean) => {
    console.log('[useLiveEvents] Setting enabled:', value, 'current liveState:', liveState);
    localStorage.setItem(LIVE_ENABLED_KEY, String(value));
    setEnabledState(value);
  }, [liveState]);

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
      console.error('[useLiveEvents] Failed to clear events:', err);
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
      console.error('[useLiveEvents] Failed to update channels:', err);
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
    liveState,
  };
}
