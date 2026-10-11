/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {

      // ─────────────────────────────────────────────────────────────
      // SENTINEL-AI DESIGN TOKEN PALETTE
      // ─────────────────────────────────────────────────────────────
      colors: {

        // Canvas & Surface Hierarchy
        canvas:   "#050609",          // Obsidian base — deepest layer
        surface:  "#0B0E14",          // Card surface — primary elevated layer
        "surface-2": "#10141C",       // Secondary elevated — headers, wells
        "surface-3": "#151B26",       // Tertiary — active/hover fill

        // Borders — 3-tier opacity stack
        "edge-subtle": "rgba(255,255,255,0.04)",   // Outermost frames
        "edge":        "rgba(255,255,255,0.08)",   // Default card/panel borders
        "edge-bright": "rgba(255,255,255,0.14)",   // Hover / focus borders

        // Primary Interactive — Electric Phosphor Cyan
        cyan: {
          DEFAULT: "#00F0FF",
          50:  "rgba(0,240,255,0.05)",
          100: "rgba(0,240,255,0.10)",
          200: "rgba(0,240,255,0.20)",
          300: "#67F7FF",
          400: "#33F4FF",
          500: "#00F0FF",
          600: "#00CCE0",
          700: "#009BB0",
          800: "#006E80",
          900: "#003D47",
          950: "#001E24",
        },

        // Threat Critical — Cadmium Crimson
        crimson: {
          DEFAULT: "#FF1E44",
          50:  "rgba(255,30,68,0.05)",
          100: "rgba(255,30,68,0.10)",
          200: "rgba(255,30,68,0.20)",
          300: "#FF7089",
          400: "#FF4462",
          500: "#FF1E44",
          600: "#E0002A",
          700: "#AD0020",
          800: "#7A0016",
          900: "#47000D",
          950: "#240006",
        },

        // Threat Warning — Electric Amber
        amber: {
          DEFAULT: "#FFAA00",
          50:  "rgba(255,170,0,0.05)",
          100: "rgba(255,170,0,0.10)",
          200: "rgba(255,170,0,0.20)",
          300: "#FFC94D",
          400: "#FFB826",
          500: "#FFAA00",
          600: "#E09600",
          700: "#AD7300",
          800: "#7A5200",
          900: "#472F00",
          950: "#241800",
        },

        // Threat Clear — Phosphor Emerald
        emerald: {
          DEFAULT: "#00E599",
          50:  "rgba(0,229,153,0.05)",
          100: "rgba(0,229,153,0.10)",
          200: "rgba(0,229,153,0.20)",
          300: "#4DEFB9",
          400: "#26EAA9",
          500: "#00E599",
          600: "#00C682",
          700: "#009960",
          800: "#006B43",
          900: "#003D26",
          950: "#001E13",
        },

        // Red-Team Adversary — Laser Violet
        violet: {
          DEFAULT: "#8B5CF6",
          50:  "rgba(139,92,246,0.05)",
          100: "rgba(139,92,246,0.10)",
          200: "rgba(139,92,246,0.20)",
          300: "#BBA0FA",
          400: "#A379F8",
          500: "#8B5CF6",
          600: "#6E38E0",
          700: "#5222AD",
          800: "#38157A",
          900: "#1F0847",
          950: "#0F0424",
        },

        // UI Neutral Scale — Warm Grey-Blue tint
        ink: {
          50:  "#F0F2F7",
          100: "#D8DCE8",
          200: "#B4BBCC",
          300: "#8892A8",
          400: "#5C6480",
          500: "#3A4060",
          600: "#252A40",
          700: "#171B2E",
          800: "#0F1220",
          900: "#080A14",
          950: "#040509",
        },
      },

      // ─────────────────────────────────────────────────────────────
      // TYPOGRAPHY SYSTEM
      // ─────────────────────────────────────────────────────────────
      fontFamily: {
        sans: [
          "Inter",
          "Geist",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "Cascadia Code",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },

      fontSize: {
        "2xs": ["0.625rem", { lineHeight: "0.875rem" }], // 10px — micro badges
        "3xs": ["0.5rem",   { lineHeight: "0.75rem" }],  // 8px  — metadata labels
      },

      letterSpacing: {
        "widest-2": "0.2em",
        "widest-3": "0.3em",
      },

      // ─────────────────────────────────────────────────────────────
      // SPACING — COMPACT DATA-DENSITY SCALE
      // ─────────────────────────────────────────────────────────────
      spacing: {
        "0.75": "0.1875rem",  // 3px
        "1.25": "0.3125rem",  // 5px
        "2.5":  "0.625rem",   // 10px — standard compact padding
        "3.5":  "0.875rem",   // 14px — comfortable compact
        "4.5":  "1.125rem",   // 18px
        "13":   "3.25rem",
        "15":   "3.75rem",
        "18":   "4.5rem",
        "22":   "5.5rem",
        "72":   "18rem",
        "80":   "20rem",
        "96":   "24rem",
      },

      // ─────────────────────────────────────────────────────────────
      // BORDER RADIUS
      // ─────────────────────────────────────────────────────────────
      borderRadius: {
        "xs":  "0.1875rem",  // 3px  — micro-chip
        "sm":  "0.25rem",    // 4px  — compact button
        DEFAULT: "0.375rem", // 6px  — standard
        "md":  "0.5rem",     // 8px  — card
        "lg":  "0.75rem",    // 12px — panel
        "xl":  "1rem",       // 16px — modal
        "2xl": "1.25rem",    // 20px — glass card
      },

      // ─────────────────────────────────────────────────────────────
      // BOX SHADOWS — GLOW SYSTEM
      // ─────────────────────────────────────────────────────────────
      boxShadow: {
        // Structural
        "panel":       "0 1px 0 0 rgba(255,255,255,0.04) inset, 0 0 0 1px rgba(255,255,255,0.06)",
        "card":        "0 2px 8px 0 rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.06)",
        "modal":       "0 24px 80px 0 rgba(0,0,0,0.80), 0 0 0 1px rgba(255,255,255,0.08)",

        // Cyber Glow Accents
        "glow-cyan":   "0 0 20px -4px rgba(0,240,255,0.35), 0 0 40px -8px rgba(0,240,255,0.15)",
        "glow-cyan-sm":"0 0 10px -2px rgba(0,240,255,0.30)",
        "glow-crimson":"0 0 20px -4px rgba(255,30,68,0.40), 0 0 40px -8px rgba(255,30,68,0.20)",
        "glow-amber":  "0 0 20px -4px rgba(255,170,0,0.35), 0 0 40px -8px rgba(255,170,0,0.15)",
        "glow-emerald":"0 0 20px -4px rgba(0,229,153,0.35), 0 0 40px -8px rgba(0,229,153,0.15)",
        "glow-violet": "0 0 20px -4px rgba(139,92,246,0.35), 0 0 40px -8px rgba(139,92,246,0.15)",

        // Inset Fills for Active States
        "inset-cyan":    "inset 0 0 16px rgba(0,240,255,0.08)",
        "inset-crimson": "inset 0 0 16px rgba(255,30,68,0.08)",
        "inset-emerald": "inset 0 0 16px rgba(0,229,153,0.08)",

        // Nav Active
        "nav-active":  "inset 0 0 12px rgba(0,240,255,0.10), 0 0 0 1px rgba(0,240,255,0.20)",
      },

      // ─────────────────────────────────────────────────────────────
      // BACKDROP BLUR
      // ─────────────────────────────────────────────────────────────
      backdropBlur: {
        "2xs": "1px",
        "xs":  "2px",
        "sm":  "4px",
        "md":  "12px",
        "lg":  "20px",
        "xl":  "32px",
      },

      // ─────────────────────────────────────────────────────────────
      // KEYFRAME ANIMATIONS
      // ─────────────────────────────────────────────────────────────
      keyframes: {
        // Subtle liveness pulse for status dots
        "pulse-dot": {
          "0%, 100%": { transform: "scale(1)", opacity: "1" },
          "50%":      { transform: "scale(1.4)", opacity: "0.6" },
        },

        // Horizontal border shimmer — for card/panel active edges
        "shimmer-border": {
          "0%":   { backgroundPosition: "200% center" },
          "100%": { backgroundPosition: "-200% center" },
        },

        // Radar sweep rotation
        "radar-sweep": {
          "0%":   { transform: "rotate(0deg)", opacity: "0.8" },
          "100%": { transform: "rotate(360deg)", opacity: "0.8" },
        },

        // Scanning line across terminal streams
        "scan-line": {
          "0%":   { top: "-4px", opacity: "0.6" },
          "100%": { top: "100%", opacity: "0" },
        },

        // Flicker for threat-critical alerts
        "threat-flicker": {
          "0%, 100%": { opacity: "1" },
          "10%":      { opacity: "0.7" },
          "20%":      { opacity: "1" },
          "30%":      { opacity: "0.8" },
          "40%":      { opacity: "1" },
        },

        // Smooth data stream wipe-in
        "stream-in": {
          "0%":   { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },

        // Fade-up for modals and panels
        "fade-up": {
          "0%":   { opacity: "0", transform: "translateY(12px) scale(0.98)" },
          "100%": { opacity: "1", transform: "translateY(0) scale(1)" },
        },

        // Border glow pulse for interactive elements
        "border-pulse": {
          "0%, 100%": { borderColor: "rgba(0,240,255,0.20)" },
          "50%":      { borderColor: "rgba(0,240,255,0.60)" },
        },

        // Number counter flash — for live telemetry metrics
        "counter-flash": {
          "0%":   { color: "#00F0FF", opacity: "1" },
          "50%":  { color: "#FFFFFF", opacity: "0.9" },
          "100%": { color: "#00F0FF", opacity: "1" },
        },

        // Blink for code cursors
        "cursor-blink": {
          "0%, 100%": { opacity: "1" },
          "50%":      { opacity: "0" },
        },

        // Diagnostic progress bar indeterminate
        "progress-indeterminate": {
          "0%":   { left: "-40%", width: "40%" },
          "60%":  { left: "100%", width: "40%" },
          "100%": { left: "100%", width: "40%" },
        },
      },

      animation: {
        "pulse-dot":               "pulse-dot 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "shimmer-border":          "shimmer-border 3s linear infinite",
        "radar-sweep":             "radar-sweep 4s linear infinite",
        "scan-line":               "scan-line 4s linear infinite",
        "threat-flicker":          "threat-flicker 2.5s ease-in-out infinite",
        "stream-in":               "stream-in 0.25s ease-out forwards",
        "fade-up":                 "fade-up 0.3s ease-out forwards",
        "border-pulse":            "border-pulse 2s ease-in-out infinite",
        "counter-flash":           "counter-flash 0.6s ease-out",
        "cursor-blink":            "cursor-blink 1s step-end infinite",
        "progress-indeterminate":  "progress-indeterminate 1.5s ease-in-out infinite",
        "spin-slow":               "spin 8s linear infinite",
      },
    },
  },
  plugins: [],
}
