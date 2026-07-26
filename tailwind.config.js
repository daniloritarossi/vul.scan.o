/**
 * Tailwind config — compiled to static/vendor/tailwind.css (replaces the old
 * in-browser Play CDN runtime). Build: `npm run css` (see package.json).
 *
 * `content` scans every template + shared JS that carries class strings so the
 * JIT emits exactly the utilities in use. Class names must appear as complete
 * literal strings (they do — the JS badge maps use full class strings), never
 * built by concatenation, or they won't be detected.
 */
module.exports = {
  content: ['./templates/**/*.html', './static/*.js'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'surface-tint': '#00daf3',
        'on-tertiary-fixed': '#23005c',
        'on-secondary-fixed-variant': '#004395',
        'on-secondary': '#002e6a',
        'surface-dim': '#f8fafc',
        'tertiary-fixed': '#e9ddff',
        'on-error': '#690005',
        'primary-fixed': '#9cf0ff',
        'on-tertiary-container': '#6834d1',
        'on-error-container': '#ffdad6',
        'inverse-on-surface': '#f1f5f9',
        'on-primary-container': '#00626e',
        error: '#ef4444',
        'surface-container-lowest': '#ffffff',
        'on-background': '#0f172a',
        'inverse-primary': '#00daf3',
        secondary: '#adc6ff',
        'secondary-container': '#0566d9',
        'primary-fixed-dim': '#06b6d4',
        'tertiary-container': '#d9c8ff',
        'surface-variant': '#f1f5f9',
        outline: '#94a3b8',
        'on-primary-fixed-variant': '#004f58',
        'surface-container-high': '#e2e8f0',
        surface: '#ffffff',
        'outline-variant': '#cbd5e1',
        primary: '#c3f5ff',
        'secondary-fixed-dim': '#3b82f6',
        'on-secondary-fixed': '#001a42',
        tertiary: '#f2e9ff',
        'primary-container': '#00e5ff',
        'secondary-fixed': '#d8e2ff',
        'tertiary-fixed-dim': '#8b5cf6',
        'on-tertiary': '#3c0091',
        'on-primary': '#00363d',
        'on-surface-variant': '#64748b',
        'error-container': '#93000a',
        'on-surface': '#1e293b',
        'on-tertiary-fixed-variant': '#5516be',
        'surface-container-low': '#f8fafc',
        'on-primary-fixed': '#001f24',
        'on-secondary-container': '#e6ecff',
        'surface-container': '#f1f5f9',
        'surface-bright': '#ffffff',
        background: '#ffffff',
        'surface-container-highest': '#cbd5e1',
        'inverse-surface': '#0f172a',
        // ── Themed core colours routed through CSS variables (see app.css). In
        //    light mode these equal the stock Tailwind palette; .dark flips the
        //    variables, so bg/border/hover/divide/opacity variants all re-theme
        //    with no per-utility override. extend deep-merges, so shades not
        //    listed here (slate-400..900, cyan-500, …) stay stock in both modes.
        white: 'rgb(var(--c-white) / <alpha-value>)',
        slate: {
          50: 'rgb(var(--c-slate-50) / <alpha-value>)',
          100: 'rgb(var(--c-slate-100) / <alpha-value>)',
          200: 'rgb(var(--c-slate-200) / <alpha-value>)',
          300: 'rgb(var(--c-slate-300) / <alpha-value>)',
        },
        cyan: {
          50: 'rgb(var(--c-cyan-50) / <alpha-value>)',
          100: 'rgb(var(--c-cyan-100) / <alpha-value>)',
          200: 'rgb(var(--c-cyan-200) / <alpha-value>)',
          300: 'rgb(var(--c-cyan-300) / <alpha-value>)',
          600: 'rgb(var(--c-cyan-600) / <alpha-value>)',
          700: 'rgb(var(--c-cyan-700) / <alpha-value>)',
          800: 'rgb(var(--c-cyan-800) / <alpha-value>)',
        },
        emerald: {
          50: 'rgb(var(--c-emerald-50) / <alpha-value>)',
          100: 'rgb(var(--c-emerald-100) / <alpha-value>)',
          200: 'rgb(var(--c-emerald-200) / <alpha-value>)',
          600: 'rgb(var(--c-emerald-600) / <alpha-value>)',
          700: 'rgb(var(--c-emerald-700) / <alpha-value>)',
        },
        rose: {
          50: 'rgb(var(--c-rose-50) / <alpha-value>)',
          100: 'rgb(var(--c-rose-100) / <alpha-value>)',
          200: 'rgb(var(--c-rose-200) / <alpha-value>)',
          300: 'rgb(var(--c-rose-300) / <alpha-value>)',
          600: 'rgb(var(--c-rose-600) / <alpha-value>)',
          700: 'rgb(var(--c-rose-700) / <alpha-value>)',
        },
        red: {
          50: 'rgb(var(--c-red-50) / <alpha-value>)',
          200: 'rgb(var(--c-red-200) / <alpha-value>)',
          700: 'rgb(var(--c-red-700) / <alpha-value>)',
        },
        amber: {
          50: 'rgb(var(--c-amber-50) / <alpha-value>)',
          200: 'rgb(var(--c-amber-200) / <alpha-value>)',
          700: 'rgb(var(--c-amber-700) / <alpha-value>)',
        },
        orange: {
          50: 'rgb(var(--c-orange-50) / <alpha-value>)',
          200: 'rgb(var(--c-orange-200) / <alpha-value>)',
          700: 'rgb(var(--c-orange-700) / <alpha-value>)',
        },
        blue: {
          50: 'rgb(var(--c-blue-50) / <alpha-value>)',
          100: 'rgb(var(--c-blue-100) / <alpha-value>)',
          200: 'rgb(var(--c-blue-200) / <alpha-value>)',
          600: 'rgb(var(--c-blue-600) / <alpha-value>)',
          700: 'rgb(var(--c-blue-700) / <alpha-value>)',
        },
        indigo: {
          50: 'rgb(var(--c-indigo-50) / <alpha-value>)',
          100: 'rgb(var(--c-indigo-100) / <alpha-value>)',
          200: 'rgb(var(--c-indigo-200) / <alpha-value>)',
          300: 'rgb(var(--c-indigo-300) / <alpha-value>)',
          600: 'rgb(var(--c-indigo-600) / <alpha-value>)',
          700: 'rgb(var(--c-indigo-700) / <alpha-value>)',
          800: 'rgb(var(--c-indigo-800) / <alpha-value>)',
        },
        purple: {
          50: 'rgb(var(--c-purple-50) / <alpha-value>)',
          200: 'rgb(var(--c-purple-200) / <alpha-value>)',
          700: 'rgb(var(--c-purple-700) / <alpha-value>)',
        },
        yellow: {
          50: 'rgb(var(--c-yellow-50) / <alpha-value>)',
          200: 'rgb(var(--c-yellow-200) / <alpha-value>)',
          700: 'rgb(var(--c-yellow-700) / <alpha-value>)',
        },
      },
      borderRadius: {
        DEFAULT: '0.25rem',
        lg: '0.5rem',
        xl: '1rem',
        full: '9999px',
      },
      spacing: {
        'base-unit': '4px',
        gutter: '16px',
        'margin-desktop': '32px',
        'margin-mobile': '16px',
        'panel-padding': '24px',
      },
      fontFamily: {
        'code-sm': ['JetBrains Mono'],
        'headline-md': ['Inter'],
        'display-lg': ['Inter'],
        'code-lg': ['JetBrains Mono'],
        'label-caps': ['Inter'],
        'body-md': ['Inter'],
      },
      fontSize: {
        'code-sm': ['13px', { lineHeight: '18px', fontWeight: '400' }],
        'headline-md': ['20px', { lineHeight: '28px', fontWeight: '600' }],
        'display-lg': ['48px', { lineHeight: '56px', letterSpacing: '-0.02em', fontWeight: '700' }],
        'code-lg': ['16px', { lineHeight: '24px', fontWeight: '500' }],
        'label-caps': ['11px', { lineHeight: '16px', letterSpacing: '0.1em', fontWeight: '700' }],
        'body-md': ['15px', { lineHeight: '24px', fontWeight: '400' }],
      },
    },
  },
};
