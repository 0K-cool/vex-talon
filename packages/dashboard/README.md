# 0K SaaS Dashboard Template

**Version:** v1 Alpha
**Updated:** February 3, 2026

Reusable dashboard template for **0K family projects** (Talon, ATHENA, Vex, and future projects).

## Design System

**Base:** Charcoal (#222222) - This template is NOT for blue-based products like DetectIQ.

### Themes (Layout)

| Theme | Description |
|-------|-------------|
| `default` | Dark backdrop behind widgets, top bar visible |
| `minimal` | Uniform charcoal background, bordered widgets, no top bar |

### Accent Colors

| Accent | Hex | Use Case |
|--------|-----|----------|
| `orange` | #c2703c | 0K default |
| `red` | #dc2626 | ATHENA (pentest) |
| `blue` | #3b82f6 | General |
| `green` | #22c55e | General |
| `purple` | #8b5cf6 | General |

## Usage

### HTML Setup

```html
<!-- 0K Default (orange accent) -->
<html data-theme="default" data-accent="orange">

<!-- ATHENA with Minimal layout -->
<html data-theme="minimal" data-accent="red">

<!-- Mix and match -->
<html data-theme="minimal" data-accent="purple">
```

### CSS Variables

All variables use the `--zerok-` prefix:

```css
var(--zerok-primary)      /* Accent color */
var(--zerok-bg)           /* Background */
var(--zerok-sidebar)      /* Sidebar background */
var(--zerok-card)         /* Widget/card background */
var(--zerok-text)         /* Primary text */
var(--zerok-text-muted)   /* Secondary text */
var(--zerok-border)       /* Border color */
```

### LocalStorage

Preferences persist automatically:
- `zerok-theme` - Layout theme (default/minimal)
- `zerok-accent` - Accent color (orange/red/blue/green/purple)

## Adding New Widgets

**Spacing Convention (IMPORTANT):**

All widget container rows MUST use consistent spacing:
- `gap: 6px` - between widgets horizontally
- `margin-bottom: 6px` - between rows vertically

```css
/* 3-column row */
.widget-grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 6px;
  margin-bottom: 6px;
}

/* 2-column row */
.two-columns {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
  margin-bottom: 6px;
}
```

When adding new widget rows, always include both `gap` and `margin-bottom` properties.

## Customizing Branding

Update the sidebar brand for your project:

```html
<span class="sidebar-title">
  <span class="brand-0k"><span class="slashed-zero">0</span>K</span>
  <span class="brand-name">YourProject</span>  <!-- Change this -->
</span>
```

## Architecture Decision

**DetectIQ** (and other blue-based products) should have their own separate template with blue backgrounds baked in. This template stays focused on the charcoal-based 0K visual identity.

*Decision made: February 3, 2026*

## File Structure

```
packages/dashboard/
├── preview.html    # Full template with theme switcher
└── README.md       # This file
```

## Preview

Open `preview.html` in a browser. Use Settings > Theme and Accent to preview combinations.

---

## Version History

### v1 Alpha (February 3, 2026)
- Initial template release
- Two layout themes: Default, Minimal
- Five accent colors: Orange, Red, Blue, Green, Purple
- Sidebar with collapsible sections
- User profile section
- Stat cards, widget grid, event lists
- Theme/accent persistence via localStorage
- CSS variables with `--zerok-*` prefix
- **Chart.js integration** with dynamic accent colors:
  - Area chart with gradient shading
  - Radar/spider chart
  - Donut chart with center overlay
- Documented spacing convention for widget rows

## Roadmap (Future)

Improvements to add as real projects reveal gaps:

- [ ] Responsive/mobile breakpoints
- [ ] Additional widget types (tables, forms, modals)
- [ ] Loading/skeleton states
- [ ] Toast notification system
- [ ] Extract to separate CSS/JS files
- [ ] Accessibility improvements (ARIA, keyboard nav)
