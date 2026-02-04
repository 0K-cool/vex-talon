export interface SecurityEvent {
  id: number | string;
  timestamp: string;
  layer: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  action: 'block' | 'warn' | 'alert' | 'log';
  description?: string;
  toolName?: string;
  patternId?: string;
}

export interface EventListProps {
  events: SecurityEvent[];
  title?: string;
  maxHeight?: string;
  onEventClick?: (event: SecurityEvent) => void;
  className?: string;
}

export function EventList({
  events,
  title = 'Recent Events',
  maxHeight = '400px',
  onEventClick,
  className = '',
}: EventListProps) {
  return (
    <div
      className={`event-list ${className}`}
      style={{
        backgroundColor: 'var(--talon-card, #141414)',
        border: '1px solid var(--talon-border, #2a2a2a)',
        borderRadius: 'var(--talon-radius-lg, 12px)',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--talon-border, #2a2a2a)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--talon-text, #fff)', margin: 0 }}>
          {title}
        </h3>
        <span style={{ fontSize: '12px', color: 'var(--talon-text-muted, #a0a0a0)' }}>
          {events.length} events
        </span>
      </div>

      <div style={{ maxHeight, overflowY: 'auto' }}>
        {events.length === 0 ? (
          <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--talon-text-dim, #666)' }}>
            No events to display
          </div>
        ) : (
          events.map((event) => (
            <EventRow key={event.id} event={event} onClick={() => onEventClick?.(event)} />
          ))
        )}
      </div>
    </div>
  );
}

function EventRow({ event, onClick }: { event: SecurityEvent; onClick?: () => void }) {
  const severityColors = {
    CRITICAL: 'var(--talon-critical, #ef4444)',
    HIGH: 'var(--talon-high, #f97316)',
    MEDIUM: 'var(--talon-medium, #eab308)',
    LOW: 'var(--talon-low, #22c55e)',
  };

  const actionIcons = {
    block: '🛑',
    warn: '⚠️',
    alert: '🔔',
    log: '📝',
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <button
      onClick={onClick}
      style={{
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '12px 20px',
        border: 'none',
        borderBottom: '1px solid var(--talon-border, #2a2a2a)',
        backgroundColor: 'transparent',
        cursor: 'pointer',
        textAlign: 'left',
        transition: 'background-color 0.15s ease',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = 'var(--talon-card-hover, #1a1a1a)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = 'transparent';
      }}
    >
      {/* Action icon */}
      <span style={{ fontSize: '14px' }}>{actionIcons[event.action]}</span>

      {/* Severity badge */}
      <span
        style={{
          padding: '2px 8px',
          fontSize: '10px',
          fontWeight: '600',
          textTransform: 'uppercase',
          borderRadius: '4px',
          backgroundColor: `${severityColors[event.severity]}20`,
          color: severityColors[event.severity],
          minWidth: '60px',
          textAlign: 'center',
        }}
      >
        {event.severity}
      </span>

      {/* Layer */}
      <span
        style={{
          fontSize: '12px',
          fontWeight: '600',
          color: 'var(--talon-primary, #c2703c)',
          width: '36px',
        }}
      >
        {event.layer}
      </span>

      {/* Description */}
      <span
        style={{
          flex: 1,
          fontSize: '13px',
          color: 'var(--talon-text, #fff)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {event.description || event.patternId || 'Security event'}
      </span>

      {/* Tool name */}
      {event.toolName && (
        <span
          style={{
            fontSize: '11px',
            color: 'var(--talon-text-muted, #a0a0a0)',
            fontFamily: 'var(--talon-font-mono)',
          }}
        >
          {event.toolName}
        </span>
      )}

      {/* Timestamp */}
      <span
        style={{
          fontSize: '11px',
          color: 'var(--talon-text-dim, #666)',
          fontFamily: 'var(--talon-font-mono)',
        }}
      >
        {formatTime(event.timestamp)}
      </span>
    </button>
  );
}
