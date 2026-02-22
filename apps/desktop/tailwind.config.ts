import type { Config } from 'tailwindcss';

export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        card: 'hsl(var(--card))',
        border: 'hsl(var(--border))',
        accent: 'hsl(var(--accent))',
        muted: 'hsl(var(--muted))',
      },
      boxShadow: {
        panel: '0 22px 70px -40px rgba(11, 26, 41, 0.75)',
      },
      keyframes: {
        'fade-up': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0px)' }
        }
      },
      animation: {
        'fade-up': 'fade-up 0.35s ease-out forwards',
      }
    },
  },
  plugins: [],
} satisfies Config;
