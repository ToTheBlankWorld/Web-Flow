import { useCallback, useRef, useState } from 'react'
import type { ThreatAlert, NotificationItem } from '../types'
import { THREAT_TYPE_LABELS, SEVERITY_CONFIG } from '../types'

const ALERT_SOUND_FREQUENCIES: Record<string, number> = {
  critical: 880,
  high: 660,
  medium: 440,
  low: 330,
  info: 220,
}

export function useNotifications() {
  const [notifications, setNotifications] = useState<NotificationItem[]>([])
  const [soundEnabled, setSoundEnabled] = useState(true)
  const [browserNotifEnabled, setBrowserNotifEnabled] = useState(false)
  const audioCtxRef = useRef<AudioContext | null>(null)

  const playAlertSound = useCallback((severity: string) => {
    if (!soundEnabled) return

    try {
      if (!audioCtxRef.current) {
        audioCtxRef.current = new AudioContext()
      }
      const ctx = audioCtxRef.current
      const oscillator = ctx.createOscillator()
      const gain = ctx.createGain()

      oscillator.connect(gain)
      gain.connect(ctx.destination)

      oscillator.frequency.value = ALERT_SOUND_FREQUENCIES[severity] || 440
      oscillator.type = severity === 'critical' ? 'square' : 'sine'

      gain.gain.setValueAtTime(0.15, ctx.currentTime)
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.5)

      oscillator.start(ctx.currentTime)
      oscillator.stop(ctx.currentTime + 0.5)

      // Double beep for critical
      if (severity === 'critical') {
        const osc2 = ctx.createOscillator()
        const gain2 = ctx.createGain()
        osc2.connect(gain2)
        gain2.connect(ctx.destination)
        osc2.frequency.value = 1100
        osc2.type = 'square'
        gain2.gain.setValueAtTime(0.15, ctx.currentTime + 0.15)
        gain2.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6)
        osc2.start(ctx.currentTime + 0.15)
        osc2.stop(ctx.currentTime + 0.6)
      }
    } catch {
      // Audio not supported
    }
  }, [soundEnabled])

  const sendBrowserNotification = useCallback((alert: ThreatAlert) => {
    if (!browserNotifEnabled) return
    if (!('Notification' in window)) return
    if (Notification.permission !== 'granted') return

    const config = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.info

    new Notification(`DNS Alert: ${THREAT_TYPE_LABELS[alert.threat_type] || alert.threat_type}`, {
      body: `${alert.domain}\n${alert.description}`,
      icon: '/favicon.ico',
      tag: alert.id,
      requireInteraction: alert.severity === 'critical',
    })
  }, [browserNotifEnabled])

  const requestBrowserPermission = useCallback(async () => {
    if (!('Notification' in window)) return false
    const result = await Notification.requestPermission()
    const granted = result === 'granted'
    setBrowserNotifEnabled(granted)
    return granted
  }, [])

  const addNotification = useCallback((alert: ThreatAlert) => {
    const notif: NotificationItem = {
      id: alert.id + '-' + Date.now(),
      timestamp: alert.timestamp,
      title: THREAT_TYPE_LABELS[alert.threat_type] || alert.threat_type,
      message: alert.description,
      severity: alert.severity,
      domain: alert.domain,
      read: false,
      threat_type: alert.threat_type,
    }

    setNotifications(prev => [notif, ...prev.slice(0, 199)])

    // Play sound for medium+ severity
    if (['critical', 'high', 'medium'].includes(alert.severity)) {
      playAlertSound(alert.severity)
    }

    // Browser notification for critical/high
    if (['critical', 'high'].includes(alert.severity)) {
      sendBrowserNotification(alert)
    }
  }, [playAlertSound, sendBrowserNotification])

  const markRead = useCallback((id: string) => {
    setNotifications(prev =>
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    )
  }, [])

  const markAllRead = useCallback(() => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })))
  }, [])

  const clearAll = useCallback(() => {
    setNotifications([])
  }, [])

  const unreadCount = notifications.filter(n => !n.read).length

  return {
    notifications,
    unreadCount,
    soundEnabled,
    setSoundEnabled,
    browserNotifEnabled,
    setBrowserNotifEnabled,
    requestBrowserPermission,
    addNotification,
    markRead,
    markAllRead,
    clearAll,
  }
}
