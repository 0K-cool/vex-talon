/**
 * StatCard Component - Display a single statistic with label and trend
 */

export interface StatCardProps {
  label: string;
  value: string | number;
  trend?: {
    value: number;
    direction: 'up' | 'down' | 'neutral';
  };
  icon?: React.ReactNode;
  className?: string;
}

export function StatCard({ label, value, trend, icon, className = '' }: StatCardProps) {
  const trendColors = {
    up: 'var(--talon-low, #22c55e)',
    down: 'var(--talon-critical, #ef4444)',
    neutral: 'var(--talon-text-muted, #a0a0a0)',
  };

  const trendIcons = {
    up: '↑',
    down: '↓',
    neutral: '→',
  };

  return (
    <div
      className={`stat-card ${className}`}
      style={{
        backgroundColor: 'var(--talon-card, #141414)',
        border: '1px solid var(--talon-border, #2a2a2a)',
        borderRadius: 'var(--talon-radius-lg, 12px)',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: '12px', color: 'var(--talon-text-muted, #a0a0a0)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {label}
        </span>
        {icon && (
          <span style={{ color: 'var(--talon-primary, #c2703c)' }}>
            {icon}
          </span>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
        <span style={{ fontSize: '28px', fontWeight: '600', color: 'var(--talon-text, #fff)' }}>
          {value}
        </span>
        {trend && (
          <span
            style={{
              fontSize: '12px',
              fontWeight: '500',
              color: trendColors[trend.direction],
              display: 'flex',
              alignItems: 'center',
              gap: '2px',
            }}
          >
            {trendIcons[trend.direction]}
            {Math.abs(trend.value)}%
          </span>
        )}
      </div>
    </div>
  );
}
