/**
 * Talon Theme - Dark orange security dashboard theme
 */

export const talonTheme = {
  colors: {
    // Primary palette
    primary: '#c2703c',
    primaryHover: '#d4844a',
    accent: '#d4844a',
    
    // Backgrounds
    background: '#0f0f0f',
    backgroundAlt: '#141414',
    card: '#141414',
    cardHover: '#1a1a1a',
    
    // Sidebar
    sidebar: '#0a0a0a',
    sidebarHover: '#1a1a1a',
    sidebarActive: '#c2703c20',
    
    // Text
    text: '#ffffff',
    textMuted: '#a0a0a0',
    textDim: '#666666',
    
    // Status colors
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    info: '#3b82f6',
    
    // Borders
    border: '#2a2a2a',
    borderHover: '#3a3a3a',
  },
  
  fonts: {
    sans: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    mono: "'JetBrains Mono', 'Fira Code', monospace",
  },
  
  radii: {
    sm: '4px',
    md: '8px',
    lg: '12px',
    xl: '16px',
  },
  
  shadows: {
    sm: '0 1px 2px rgba(0, 0, 0, 0.5)',
    md: '0 4px 6px rgba(0, 0, 0, 0.5)',
    lg: '0 10px 15px rgba(0, 0, 0, 0.5)',
    glow: '0 0 20px rgba(194, 112, 60, 0.3)',
  },
};

export type TalonTheme = typeof talonTheme;

// CSS variables for use in stylesheets
export const talonCSSVariables = `
  :root {
    --talon-primary: ${talonTheme.colors.primary};
    --talon-primary-hover: ${talonTheme.colors.primaryHover};
    --talon-accent: ${talonTheme.colors.accent};
    --talon-bg: ${talonTheme.colors.background};
    --talon-bg-alt: ${talonTheme.colors.backgroundAlt};
    --talon-card: ${talonTheme.colors.card};
    --talon-card-hover: ${talonTheme.colors.cardHover};
    --talon-sidebar: ${talonTheme.colors.sidebar};
    --talon-sidebar-hover: ${talonTheme.colors.sidebarHover};
    --talon-sidebar-active: ${talonTheme.colors.sidebarActive};
    --talon-text: ${talonTheme.colors.text};
    --talon-text-muted: ${talonTheme.colors.textMuted};
    --talon-text-dim: ${talonTheme.colors.textDim};
    --talon-critical: ${talonTheme.colors.critical};
    --talon-high: ${talonTheme.colors.high};
    --talon-medium: ${talonTheme.colors.medium};
    --talon-low: ${talonTheme.colors.low};
    --talon-info: ${talonTheme.colors.info};
    --talon-border: ${talonTheme.colors.border};
    --talon-border-hover: ${talonTheme.colors.borderHover};
    --talon-font-sans: ${talonTheme.fonts.sans};
    --talon-font-mono: ${talonTheme.fonts.mono};
    --talon-radius-sm: ${talonTheme.radii.sm};
    --talon-radius-md: ${talonTheme.radii.md};
    --talon-radius-lg: ${talonTheme.radii.lg};
    --talon-radius-xl: ${talonTheme.radii.xl};
  }
`;
