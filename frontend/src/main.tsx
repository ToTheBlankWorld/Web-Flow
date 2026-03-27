import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './index.css'

// Note: StrictMode disabled to prevent Leaflet map double-initialization issues
// React StrictMode double-mounts components which breaks Leaflet's container detection
ReactDOM.createRoot(document.getElementById('root')!).render(
  <App />
)
