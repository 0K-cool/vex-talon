import * as React from 'react';

export interface NavItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  href?: string;
  badge?: number;
  children?: NavItem[];
}

export interface SidebarProps {
  logo?: React.ReactNode;
  title?: string;
  items: NavItem[];
  activeId?: string;
  collapsed?: boolean;
  onItemClick?: (item: NavItem) => void;
  onCollapseToggle?: () => void;
  className?: string;
}

export function Sidebar({
  logo,
  title = 'Talon',
  items,
  activeId,
  collapsed = false,
  onItemClick,
  className = '',
}: SidebarProps) {
  return (
    <aside
      className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''} ${className}`}
      style={{
        width: collapsed ? '64px' : '240px',
        minHeight: '100vh',
        backgroundColor: 'var(--talon-sidebar, #0a0a0a)',
        borderRight: '1px solid var(--talon-border, #2a2a2a)',
        display: 'flex',
        flexDirection: 'column',
        transition: 'width 0.2s ease',
      }}
    >
      {/* Logo/Brand Section */}
      <div
        className="sidebar__header"
        style={{
          padding: '16px',
          borderBottom: '1px solid var(--talon-border, #2a2a2a)',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        {logo || (
          <div
            style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, var(--talon-primary, #c2703c), var(--talon-accent, #d4844a))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 'bold',
              fontSize: '14px',
              color: 'white',
            }}
          >
            T
          </div>
        )}
        {!collapsed && (
          <span
            style={{
              fontSize: '18px',
              fontWeight: '600',
              color: 'var(--talon-text, #fff)',
            }}
          >
            {title}
          </span>
        )}
      </div>

      {/* Navigation Items */}
      <nav
        className="sidebar__nav"
        style={{
          flex: 1,
          padding: '8px',
          overflowY: 'auto',
        }}
      >
        {items.map((item) => (
          <SidebarNavItem
            key={item.id}
            item={item}
            isActive={activeId === item.id}
            collapsed={collapsed}
            onClick={() => onItemClick?.(item)}
          />
        ))}
      </nav>

      {/* Footer */}
      <div
        className="sidebar__footer"
        style={{
          padding: '16px',
          borderTop: '1px solid var(--talon-border, #2a2a2a)',
        }}
      >
        {!collapsed && (
          <div
            style={{
              fontSize: '11px',
              color: 'var(--talon-text-dim, #666)',
              textAlign: 'center',
            }}
          >
            Talon Security v0.1.0
          </div>
        )}
      </div>
    </aside>
  );
}

function SidebarNavItem({
  item,
  isActive,
  collapsed,
  onClick,
}: {
  item: NavItem;
  isActive: boolean;
  collapsed: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      title={collapsed ? item.label : undefined}
      style={{
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: collapsed ? '12px' : '10px 12px',
        marginBottom: '4px',
        border: 'none',
        borderRadius: 'var(--talon-radius-md, 8px)',
        backgroundColor: isActive
          ? 'var(--talon-sidebar-active, #c2703c20)'
          : 'transparent',
        color: isActive
          ? 'var(--talon-primary, #c2703c)'
          : 'var(--talon-text-muted, #a0a0a0)',
        cursor: 'pointer',
        transition: 'all 0.15s ease',
        justifyContent: collapsed ? 'center' : 'flex-start',
        fontSize: '14px',
        fontWeight: isActive ? '500' : '400',
      }}
      onMouseEnter={(e) => {
        if (!isActive) {
          e.currentTarget.style.backgroundColor = 'var(--talon-sidebar-hover, #1a1a1a)';
          e.currentTarget.style.color = 'var(--talon-text, #fff)';
        }
      }}
      onMouseLeave={(e) => {
        if (!isActive) {
          e.currentTarget.style.backgroundColor = 'transparent';
          e.currentTarget.style.color = 'var(--talon-text-muted, #a0a0a0)';
        }
      }}
    >
      {item.icon && <span style={{ flexShrink: 0 }}>{item.icon}</span>}
      {!collapsed && <span style={{ flex: 1, textAlign: 'left' }}>{item.label}</span>}
      {!collapsed && item.badge !== undefined && item.badge > 0 && (
        <span
          style={{
            backgroundColor: 'var(--talon-critical, #ef4444)',
            color: 'white',
            fontSize: '11px',
            fontWeight: '600',
            padding: '2px 6px',
            borderRadius: '10px',
            minWidth: '18px',
            textAlign: 'center',
          }}
        >
          {item.badge > 99 ? '99+' : item.badge}
        </span>
      )}
    </button>
  );
}
