// Tailwind Play CDN config: DESIGN.md tokens mapped to the CSS variables in theme.css.
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
        night: token('night'),
        ink: token('ink'),
        'hairline-violet': token('hairline-violet'),
        'on-dark-muted': token('on-dark-muted'),
        'on-dark-faint': token('on-dark-faint'),
        lime: token('lime'),
        pink: token('pink'),
        violet: { DEFAULT: token('violet'), deep: token('violet-deep'), mid: token('violet-mid') },
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
