import { useEffect, useRef, useState, useCallback } from 'react';

export interface LiveEvent {
  id: number;
  timestamp: string;
  level: string;
  source: string;
  log_name: string;
  computer: string;
  user?: string;
  message: string;
  event_id: number;
  ip_address?: string;
}

export interface UseLiveEventsOptions {
  channels?: string[];
  query?: string;
  maxEvents?: number;
  onError?: (error: string) => void;
  onConnected?: () => void;
  onDisconnected?: () => void;
}

interface WSMessage {
  type: 'connected' | 'event' | 'heartbeat' | 'error' | 'subscribed' | 'unsubscribed';
  data?: any;
  message?: string;
  code?: string;
}

const LIVE_ENABLED_KEY = 'winalog_live_enabled';

export function useLiveEvents(options: UseLiveEventsOptions = {}) {
  const {
    channels = ['Security', 'System', 'Application'],
    query = '',
    maxEvents = 100,
    onError,
    onConnected,
    onDisconnected,
  } = options;

  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [enabled, setEnabled] = useState(() => {
    const saved = localStorage.getItem(LIVE_ENABLED_KEY);
    return saved === 'true';
  });
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempts = useRef(0);
  const subscribedRef = useRef(false);

  const handleSetEnabled = useCallback((value: boolean) => {
    localStorage.setItem(LIVE_ENABLED_KEY, String(value));
    setEnabled(value);
  }, []);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    subscribedRef.current = false;
    setIsConnected(false);
    setIsConnecting(false);
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setIsConnecting(true);

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/live/stream`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setIsConnecting(false);
      reconnectAttempts.current = 0;
      onConnected?.();

      if (!subscribedRef.current) {
        ws.send(JSON.stringify({
          action: 'subscribe',
          channels,
          query,
        }));
        subscribedRef.current = true;
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);

        switch (msg.type) {
          case 'event':
            if (msg.data) {
              setEvents(prev => [msg.data, ...prev].slice(0, maxEvents));
            }
            break;
          case 'heartbeat':
            break;
          case 'error':
            onError?.(msg.message || 'Unknown error');
            break;
          case 'connected':
            break;
        }
      } catch (e) {
        console.error('Failed to parse message:', e);
      }
    };

    ws.onerror = () => {
      onError?.('WebSocket connection error');
    };

    ws.onclose = () => {
      setIsConnected(false);
      setIsConnecting(false);
      wsRef.current = null;
      subscribedRef.current = false;
      onDisconnected?.();

      if (enabled) {
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
        reconnectAttempts.current++;
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, delay);
      }
    };
  }, [channels.join(','), query, maxEvents, enabled]);

  useEffect(() => {
    if (enabled) {
      connect();
    } else {
      disconnect();
    }
  }, [enabled]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    events,
    isConnected,
    isConnecting,
    enabled,
    setEnabled: handleSetEnabled,
    clearEvents,
    disconnect,
    connect,
  };
}
