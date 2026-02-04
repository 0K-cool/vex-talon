/**
 * TopBar Component - Dashboard header with alerts and profile
 */

export interface TopBarProps {
  title?: string;
  alertCount?: number;
  onMenuClick?: () => void;
  onAlertsClick?: () => void;
  onProfileClick?: () => void;
}

export function TopBar({
  title = 'Security Dashboard',
  alertCount = 0,
  onMenuClick,
  onAlertsClick,
  onProfileClick,
}: TopBarProps) {
  return (
    <header
      style={{
        height: '60px',
        backgroundColor: 'var(--talon-card, #141414)',
        borderBottom: '1px solid var(--talon-border, #2a2a2a)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 20px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <button
          onClick={onMenuClick}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--talon-text-muted, #a0a0a0)',
            cursor: 'pointer',
            padding: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          aria-label="Toggle sidebar"
        >
          <svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
            <path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z" />
          </svg>
        </button>
        <h1 style={{ fontSize: '16px', fontWeight: '600', color: 'var(--talon-text, #fff)', margin: 0 }}>
          {title}
        </h1>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <button
          onClick={onAlertsClick}
          style={{
            position: 'relative',
            background: 'none',
            border: 'none',
            color: 'var(--talon-text-muted, #a0a0a0)',
            cursor: 'pointer',
            padding: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          aria-label={`Alerts: ${alertCount}`}
        >
          <svg width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.89 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z" />
          </svg>
          {alertCount > 0 && (
            <span
              style={{
                position: 'absolute',
                top: '4px',
                right: '4px',
                backgroundColor: 'var(--talon-critical, #ef4444)',
                color: 'white',
                fontSize: '10px',
                fontWeight: '600',
                borderRadius: '50%',
                minWidth: '16px',
                height: '16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {alertCount > 99 ? '99+' : alertCount}
            </span>
          )}
        </button>

        <button
          onClick={onProfileClick}
          style={{
            width: '32px',
            height: '32px',
            borderRadius: '50%',
            backgroundColor: 'var(--talon-primary, #c2703c)',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'white',
            fontSize: '14px',
            fontWeight: '600',
          }}
          aria-label="Profile"
        >
          V
        </button>
      </div>
    </header>
  );
}
