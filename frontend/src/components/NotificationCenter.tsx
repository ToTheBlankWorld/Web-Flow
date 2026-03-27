import React, { useState } from 'react'
import { X, Bell, Trash2, CheckCheck, AlertTriangle } from 'lucide-react'
import type { NotificationItem } from '../types'
import { SEVERITY_CONFIG, THREAT_TYPE_LABELS } from '../types'

interface Props {
  notifications: NotificationItem[]
  isOpen: boolean
  onClose: () => void
  onClear: () => void
  onMarkAllRead: () => void
  onMarkRead: (id: string) => void
}

export const NotificationCenter: React.FC<Props> = ({
  notifications,
  isOpen,
  onClose,
  onClear,
  onMarkAllRead,
  onMarkRead,
}) => {
  const [filter, setFilter] = useState<'all' | 'unread'>('all')

  const filteredNotifications = filter === 'unread'
    ? notifications.filter(n => !n.read)
    : notifications

  const unreadCount = notifications.filter(n => !n.read).length

  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts)
      const now = new Date()
      const diff = (now.getTime() - d.getTime()) / 1000

      if (diff < 60) return 'Just now'
      if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
      if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
      return d.toLocaleDateString()
    } catch {
      return ts
    }
  }

  return (
    <>
      {/* Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
          onClick={onClose}
        />
      )}

      {/* Panel */}
      <div
        className={`notification-panel ${isOpen ? 'translate-x-0' : 'translate-x-full'}`}
        style={{ transition: 'transform 0.3s ease' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-surface-700/50">
          <div className="flex items-center gap-2">
            <Bell className="w-5 h-5 text-brand-400" />
            <h2 className="text-base font-semibold text-surface-200">Notifications</h2>
            {unreadCount > 0 && (
              <span className="bg-red-500 text-white text-xs font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
                {unreadCount}
              </span>
            )}
          </div>
          <button onClick={onClose} className="text-surface-400 hover:text-surface-200 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Filters + Actions */}
        <div className="flex items-center justify-between px-5 py-2 border-b border-surface-700/30">
          <div className="flex gap-2">
            <button
              onClick={() => setFilter('all')}
              className={`text-xs px-2.5 py-1 rounded-md ${filter === 'all' ? 'bg-brand-500/20 text-brand-400' : 'text-surface-400 hover:text-surface-200'}`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('unread')}
              className={`text-xs px-2.5 py-1 rounded-md ${filter === 'unread' ? 'bg-brand-500/20 text-brand-400' : 'text-surface-400 hover:text-surface-200'}`}
            >
              Unread ({unreadCount})
            </button>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onMarkAllRead}
              className="text-xs text-surface-400 hover:text-surface-200 flex items-center gap-1"
              title="Mark all as read"
            >
              <CheckCheck className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={onClear}
              className="text-xs text-surface-400 hover:text-red-400 flex items-center gap-1"
              title="Clear all"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Notification List */}
        <div className="overflow-y-auto" style={{ height: 'calc(100% - 110px)' }}>
          {filteredNotifications.length === 0 ? (
            <div className="text-center py-12">
              <Bell className="w-10 h-10 text-surface-600 mx-auto mb-3" />
              <p className="text-surface-500 text-sm">No notifications</p>
            </div>
          ) : (
            filteredNotifications.map((notif) => {
              const config = SEVERITY_CONFIG[notif.severity] || SEVERITY_CONFIG.info

              return (
                <div
                  key={notif.id}
                  className={`px-5 py-3 border-b border-surface-700/20 cursor-pointer transition-colors hover:bg-surface-800/50 ${
                    !notif.read ? 'bg-surface-800/30' : ''
                  }`}
                  onClick={() => onMarkRead(notif.id)}
                >
                  <div className="flex items-start gap-3">
                    {/* Severity dot */}
                    <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${config.dot}`}></div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-xs font-semibold ${config.text}`}>
                          {notif.title}
                        </span>
                        {!notif.read && (
                          <span className="w-1.5 h-1.5 rounded-full bg-brand-400"></span>
                        )}
                      </div>
                      <p className="text-xs text-surface-400 mb-1 truncate">{notif.message}</p>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-surface-500 font-mono">{notif.domain}</span>
                        <span className="text-[10px] text-surface-600">{formatTime(notif.timestamp)}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </>
  )
}
