// Tailwind Play CDN config: palette tokens mapped to the CSS variables in theme.css.
const token = (name) => `oklch(var(--${name}) / <alpha-value>)`

tailwind.config = {
  theme: {
    extend: {
      colors: {
        background: token('background'),
        foreground: token('foreground'),
        card: { DEFAULT: token('card'), foreground: token('card-foreground') },
        primary: { DEFAULT: token('primary'), foreground: token('primary-foreground') },
        muted: { DEFAULT: token('muted'), foreground: token('muted-foreground') },
        accent: { DEFAULT: token('accent'), foreground: token('accent-foreground') },
        border: token('border'),
        input: token('input'),
        ring: token('ring'),
        sidebar: token('sidebar'),
        sunken: token('sunken'),
        'on-dark-muted': token('on-dark-muted'),
        'on-dark-faint': token('on-dark-faint'),
        brand: token('brand'),
        link: token('link'),
        gold: token('gold'),
        ink: token('ink'),
        critical: token('critical'),
        high: token('high'),
        ok: token('ok'),
        info: token('info'),
      },
      borderColor: { DEFAULT: token('border') },
      fontFamily: {
        sans: ['Rubik', '-apple-system', 'system-ui', 'Segoe UI', 'Helvetica', 'Arial', 'sans-serif'],
        display: ['"Space Grotesk"', 'Rubik', 'system-ui', 'sans-serif'],
        mono: ['Monaco', 'Menlo', '"Ubuntu Mono"', 'monospace'],
      },
      borderRadius: { xs: '4px', sm: '6px', md: '8px', lg: '10px', xl: '12px', '2xl': '18px' },
      maxWidth: { content: '1152px' },
    },
  },
}
