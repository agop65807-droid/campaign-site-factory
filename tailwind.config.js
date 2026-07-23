module.exports = {
  content: [
    './index.html',
    './campaign.html',
    './admin.html',
    './assets/js/**/*.js'
  ],
  theme: {
    extend: {
      colors: {
        primary: 'rgb(var(--c-primary) / <alpha-value>)',
        secondary: 'rgb(var(--c-secondary) / <alpha-value>)',
        surface: 'rgb(var(--c-surface) / <alpha-value>)',
        border: 'rgb(var(--c-border) / <alpha-value>)',
        muted: 'rgb(var(--c-muted) / <alpha-value>)'
      },
      boxShadow: {
        glass: '0 8px 32px rgba(0,0,0,0.25)',
        card: '0 10px 30px rgba(0,0,0,0.18)'
      },
      borderRadius: {
        xl2: '1.25rem'
      }
    }
  },
  plugins: []
}
