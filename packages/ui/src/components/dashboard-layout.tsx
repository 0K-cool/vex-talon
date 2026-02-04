import * as React from 'react';
import { Sidebar, type NavItem } from './sidebar';
import { TopBar } from './topbar';

export interface DashboardLayoutProps {
  navItems: NavItem[];
  activeNavId?: string;
  sidebarTitle?: string;
  sidebarLogo?: React.ReactNode;
  topBarTitle?: string;
  alertCount?: number;
  children: React.ReactNode;
  onNavItemClick?: (item: NavItem) => void;
  onAlertsClick?: () => void;
  onProfileClick?: () => void;
}

export function DashboardLayout({
  navItems,
  activeNavId,
  sidebarTitle = 'Talon',
  sidebarLogo,
  topBarTitle,
  alertCount = 0,
  children,
  onNavItemClick,
  onAlertsClick,
  onProfileClick,
}: DashboardLayoutProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = React.useState(false);

  return (
    <div
      className="dashboard-layout"
      style={{
        display: 'flex',
        minHeight: '100vh',
        backgroundColor: 'var(--talon-bg, #0f0f0f)',
        color: 'var(--talon-text, #fff)',
        fontFamily: 'var(--talon-font-sans)',
      }}
    >
      {/* Left Sidebar */}
      <Sidebar
        title={sidebarTitle}
        logo={sidebarLogo}
        items={navItems}
        activeId={activeNavId}
        collapsed={sidebarCollapsed}
        onItemClick={onNavItemClick}
      />

      {/* Main Area (TopBar + Content) */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top Bar */}
        <TopBar
          title={topBarTitle}
          alertCount={alertCount}
          onMenuClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          onAlertsClick={onAlertsClick}
          onProfileClick={onProfileClick}
        />

        {/* Main Content Area */}
        <main
          className="dashboard-content"
          style={{
            flex: 1,
            padding: '24px',
            overflowY: 'auto',
          }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
