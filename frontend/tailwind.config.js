/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        "soc-bg": "#030712",
        "soc-surface": "#0B1222",
        "soc-card": "rgba(15, 23, 42, 0.75)",
        "soc-border": "#1E293B",
        "soc-accent": "#38BDF8",
        "soc-danger": "#EF4444",
        "soc-warning": "#F59E0B",
        "soc-success": "#10B981",
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      backdropBlur: {
        xs: "2px",
        sm: "4px",
        md: "12px",
        lg: "16px",
      },
      boxShadow: {
        "soc-glow": "0 0 15px -3px rgba(56, 189, 248, 0.25)",
        "soc-danger-glow": "0 0 15px -3px rgba(239, 68, 68, 0.35)",
        "soc-success-glow": "0 0 15px -3px rgba(16, 185, 129, 0.35)",
      },
    },
  },
  plugins: [],
}
