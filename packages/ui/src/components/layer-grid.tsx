import * as React from 'react';

export interface LayerStatus {
  layer: string;
  name: string;
  status: 'active' | 'disabled' | 'error';
  invocations: number;
  blocks: number;
  lastInvoked?: string;
}

export interface LayerGridProps {
  layers: LayerStatus[];
  onLayerClick?: (layer: LayerStatus) => void;
  className?: string;
}

export function LayerGrid({ layers, onLayerClick, className = '' }: LayerGridProps) {
  return (
    <div
      className={`layer-grid ${className}`}
      style={{
        backgroundColor: 'var(--talon-card, #141414)',
        border: '1px solid var(--talon-border, #2a2a2a)',
        borderRadius: 'var(--talon-radius-lg, 12px)',
        padding: '20px',
      }}
    >
      <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--talon-text, #fff)', margin: '0 0 16px 0' }}>
        Defense Layers (L0-L19)
      </h3>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(10, 1fr)',
          gap: '8px',
        }}
      >
        {layers.map((layer) => (
          <LayerCell key={layer.layer} layer={layer} onClick={() => onLayerClick?.(layer)} />
        ))}
      </div>
    </div>
  );
}

function LayerCell({ layer, onClick }: { layer: LayerStatus; onClick?: () => void }) {
  const statusColors = {
    active: 'var(--talon-primary, #c2703c)',
    disabled: 'var(--talon-text-dim, #666)',
    error: 'var(--talon-critical, #ef4444)',
  };

  const bgColors = {
    active: 'rgba(194, 112, 60, 0.15)',
    disabled: 'rgba(102, 102, 102, 0.1)',
    error: 'rgba(239, 68, 68, 0.15)',
  };

  return (
    <button
      onClick={onClick}
      title={`${layer.name}\nStatus: ${layer.status}\nInvocations: ${layer.invocations}\nBlocks: ${layer.blocks}`}
      style={{
        aspectRatio: '1',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '2px',
        border: `1px solid ${statusColors[layer.status]}40`,
        borderRadius: 'var(--talon-radius-md, 8px)',
        backgroundColor: bgColors[layer.status],
        cursor: 'pointer',
        transition: 'all 0.15s ease',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'scale(1.05)';
        e.currentTarget.style.borderColor = statusColors[layer.status];
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'scale(1)';
        e.currentTarget.style.borderColor = `${statusColors[layer.status]}40`;
      }}
    >
      <span style={{ fontSize: '11px', fontWeight: '600', color: statusColors[layer.status] }}>
        {layer.layer}
      </span>
      {layer.blocks > 0 && (
        <span style={{ fontSize: '9px', color: 'var(--talon-critical, #ef4444)' }}>
          {layer.blocks}
        </span>
      )}
    </button>
  );
}

export interface LayerListProps {
  layers: LayerStatus[];
  onLayerClick?: (layer: LayerStatus) => void;
  className?: string;
}

export function LayerList({ layers, onLayerClick, className = '' }: LayerListProps) {
  return (
    <div
      className={`layer-list ${className}`}
      style={{
        backgroundColor: 'var(--talon-card, #141414)',
        border: '1px solid var(--talon-border, #2a2a2a)',
        borderRadius: 'var(--talon-radius-lg, 12px)',
        overflow: 'hidden',
      }}
    >
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--talon-border, #2a2a2a)' }}>
        <h3 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--talon-text, #fff)', margin: 0 }}>
          Layer Details
        </h3>
      </div>
      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        {layers.map((layer) => (
          <LayerRow key={layer.layer} layer={layer} onClick={() => onLayerClick?.(layer)} />
        ))}
      </div>
    </div>
  );
}

function LayerRow({ layer, onClick }: { layer: LayerStatus; onClick?: () => void }) {
  const statusColors = {
    active: 'var(--talon-low, #22c55e)',
    disabled: 'var(--talon-text-dim, #666)',
    error: 'var(--talon-critical, #ef4444)',
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
      {/* Layer badge */}
      <span
        style={{
          width: '40px',
          fontSize: '12px',
          fontWeight: '600',
          color: 'var(--talon-primary, #c2703c)',
        }}
      >
        {layer.layer}
      </span>

      {/* Name */}
      <span style={{ flex: 1, fontSize: '13px', color: 'var(--talon-text, #fff)' }}>
        {layer.name}
      </span>

      {/* Stats */}
      <span style={{ fontSize: '12px', color: 'var(--talon-text-muted, #a0a0a0)', width: '80px' }}>
        {layer.invocations.toLocaleString()} calls
      </span>
      <span style={{ fontSize: '12px', color: 'var(--talon-critical, #ef4444)', width: '60px' }}>
        {layer.blocks} blocked
      </span>

      {/* Status dot */}
      <span
        style={{
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          backgroundColor: statusColors[layer.status],
        }}
      />
    </button>
  );
}
