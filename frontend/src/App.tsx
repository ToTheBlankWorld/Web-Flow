import React, { useEffect, useRef, useState } from 'react';
import { DNSTraffic } from './components/DNSTraffic';
import { ThreatIntelligence } from './components/ThreatIntelligence';
import { KeyMetrics } from './components/KeyMetrics';
import { DetectionTimeline } from './components/DetectionTimeline';

interface DNSLog {
  timestamp: string;
  domain: string;
  src_ip: string;
  dest_ip: string;
  query_type: string;
  ttl: number;
  response_code: string;
  alert_level: string;
  alert_reason: string;
  severity: string;
}

function App() {
  const [logs, setLogs] = useState<DNSLog[]>([]);
  const [alerts, setAlerts] = useState<DNSLog[]>([]);
  const [stats, setStats] = useState({
    totalQueries: 0,
    alertRate: '0.0',
    totalDomains: 0,
    activeConnections: 0,
    threatsBlocked: 0,
  });
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const connectWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//localhost:9000/ws/logs`;

    try {
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('WebSocket connected');
        setConnected(true);
        setError(null);
      };

      ws.onmessage = (event) => {
        try {
          const log: DNSLog = JSON.parse(event.data);
          setLogs((prev) => [log, ...prev.slice(0, 499)]);

          if (log.alert_level === 'ALERT') {
            setAlerts((prev) => [log, ...prev.slice(0, 99)]);
          }
        } catch (e) {
          console.error('Error parsing message:', e);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError('Connection lost');
        setConnected(false);
      };

      ws.onclose = () => {
        setConnected(false);
        setTimeout(connectWebSocket, 3000);
      };

      wsRef.current = ws;
    } catch (e) {
      console.error('Error creating WebSocket:', e);
      setError('Failed to connect');
    }
  };

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch('http://213.199.63.247:9000/api/stats');
        const data = await response.json();

        const totalQueries = logs.length;
        const alertsCount = alerts.length;
        const alertRate = totalQueries > 0 ? ((alertsCount / totalQueries) * 100).toFixed(1) : '0.0';

        setStats({
          totalQueries,
          alertRate,
          totalDomains: data.total_domains_tracked || 0,
          activeConnections: data.active_websocket_connections || 0,
          threatsBlocked: alertsCount,
        });
      } catch (e) {
        console.error('Error fetching stats:', e);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [logs, alerts]);

  return (
    <div className="min-h-screen bg-black text-white font-mono overflow-x-hidden">
      {/* Professional Header */}
      <header className="border-b border-gray-700 px-12 py-6">
        <div className="flex justify-between items-center mb-4">
          <div>
            <p className="text-hacker-blue text-xs mb-2">// REAL-TIME DNS SECURITY ANALYSIS</p>
            <h1 className="text-5xl font-black">
              <span className="text-hacker-red">DNS</span> <span className="text-white">GUARDIAN</span>
            </h1>
            <p className="text-gray-500 text-sm mt-1">Advanced Threat Detection & Network Analysis</p>
          </div>
          <div className="text-right">
            <div className={`flex items-center gap-2 mb-2 ${connected ? 'text-hacker-green' : 'text-hacker-red'}`}>
              <span className={`w-3 h-3 rounded-full ${connected ? 'bg-hacker-green animate-pulse' : 'bg-hacker-red'}`}></span>
              <span className="text-sm font-bold">{connected ? 'LIVE' : 'OFFLINE'}</span>
            </div>
            {error && <p className="text-hacker-red text-xs">{error}</p>}
          </div>
        </div>
      </header>

      {/* Key Metrics Section */}
      <KeyMetrics stats={stats} />

      {/* Main Content Grid */}
      <div className="px-12 py-8 space-y-8">
        {/* DNS Traffic Analysis */}
        <section>
          <h2 className="text-hacker-blue text-sm font-bold mb-4">// NETWORK TRAFFIC ANALYSIS</h2>
          <DNSTraffic logs={logs} />
        </section>

        {/* Threat Intelligence & Detection Timeline */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <section>
            <h2 className="text-hacker-red text-sm font-bold mb-4">// THREAT DETECTIONS</h2>
            <ThreatIntelligence alerts={alerts} />
          </section>

          <section>
            <h2 className="text-yellow-400 text-sm font-bold mb-4">// DETECTION TIMELINE</h2>
            <DetectionTimeline alerts={alerts} />
          </section>
        </div>
      </div>
    </div>
  );
}

export default App;
