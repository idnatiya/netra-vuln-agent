// Tailwind Play CDN config: shadcn color names mapped to the CSS variables in theme.css.
const token = (name) => `oklch(var(--${name}) / <alpha-value>)`

tailwind.config = {
  theme: {
    extend: {
      colors: {
        background: token('background'),
        foreground: token('foreground'),
        card: { DEFAULT: token('card'), foreground: token('card-foreground') },
        popover: { DEFAULT: token('popover'), foreground: token('popover-foreground') },
        primary: { DEFAULT: token('primary'), foreground: token('primary-foreground') },
        secondary: { DEFAULT: token('secondary'), foreground: token('secondary-foreground') },
        muted: { DEFAULT: token('muted'), foreground: token('muted-foreground') },
        accent: { DEFAULT: token('accent'), foreground: token('accent-foreground') },
        destructive: token('destructive'),
        border: token('border'),
        input: token('input'),
        ring: token('ring'),
        terminal: token('terminal'),
        sidebar: { DEFAULT: token('sidebar'), footer: token('sidebar-footer') },
        'sev-critical': token('sev-critical'),
        'sev-high': token('sev-high'),
        'sev-medium': token('sev-medium'),
        'sev-low': token('sev-low'),
        ok: token('ok'),
      },
      borderColor: { DEFAULT: token('border') },
      fontFamily: {
        sans: ['Geist', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['Geist Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
}
