/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'hacker-dark': '#0a0e27',
        'hacker-green': '#0ff01f',
        'hacker-red': '#ff3333',
        'hacker-blue': '#00BFFF',
      }
    },
  },
  plugins: [],
}
