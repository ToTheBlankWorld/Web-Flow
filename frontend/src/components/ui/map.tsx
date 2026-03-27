"use client"

import * as React from "react"
import {
  MapContainer,
  TileLayer,
  CircleMarker,
  Popup,
  ZoomControl,
  useMap,
} from "react-leaflet"
import L from "leaflet"
import type { LatLngExpression } from "leaflet"
import "leaflet/dist/leaflet.css"

// Map Component - uses unique key to prevent re-initialization issues
interface MapProps {
  center?: LatLngExpression
  zoom?: number
  className?: string
  style?: React.CSSProperties
  children?: React.ReactNode
  scrollWheelZoom?: boolean
  zoomControl?: boolean
}

export const Map: React.FC<MapProps> = ({
  center = [20, 0],
  zoom = 2,
  className,
  style,
  children,
  scrollWheelZoom = true,
  zoomControl = true,
}) => {
  // Generate unique ID for this map instance
  const mapId = React.useId()
  const [mapKey, setMapKey] = React.useState(0)

  const containerStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    minHeight: 400,
    ...style,
  }

  return (
    <div className={className} style={containerStyle}>
      <MapContainer
        key={`map-${mapId}-${mapKey}`}
        center={center}
        zoom={zoom}
        scrollWheelZoom={scrollWheelZoom}
        zoomControl={false}
        style={{ width: "100%", height: "100%", background: "#0f172a" }}
      >
        {zoomControl && <ZoomControl position="bottomright" />}
        {children}
      </MapContainer>
    </div>
  )
}

// MapTileLayer Component
interface MapTileLayerProps {
  url?: string
  attribution?: string
  variant?: "dark" | "light" | "satellite"
}

const TILE_URLS = {
  dark: "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
  light: "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
  satellite: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
}

export const MapTileLayer: React.FC<MapTileLayerProps> = ({
  url,
  attribution = '&copy; <a href="https://carto.com">CARTO</a>',
  variant = "dark",
}) => {
  const tileUrl = url || TILE_URLS[variant]
  return <TileLayer url={tileUrl} attribution={attribution} maxZoom={19} />
}

// MapCircleMarker Component
interface MapCircleMarkerProps {
  position: LatLngExpression
  radius?: number
  color?: string
  fillColor?: string
  fillOpacity?: number
  weight?: number
  children?: React.ReactNode
}

export const MapCircleMarker: React.FC<MapCircleMarkerProps> = ({
  position,
  radius = 8,
  color = "#22d3ee",
  fillColor,
  fillOpacity = 0.8,
  weight = 1,
  children,
}) => {
  return (
    <CircleMarker
      center={position}
      radius={radius}
      pathOptions={{
        color,
        fillColor: fillColor || color,
        fillOpacity,
        weight,
      }}
    >
      {children}
    </CircleMarker>
  )
}

// MapPopup Component
interface MapPopupProps {
  children?: React.ReactNode
  className?: string
}

export const MapPopup: React.FC<MapPopupProps> = ({ children, className }) => {
  return <Popup className={className}>{children}</Popup>
}

// AutoFitBounds Component - fits map to show all markers
interface AutoFitBoundsProps {
  positions: LatLngExpression[]
  padding?: [number, number]
  maxZoom?: number
}

export const AutoFitBounds: React.FC<AutoFitBoundsProps> = ({
  positions,
  padding = [40, 40],
  maxZoom = 6,
}) => {
  const map = useMap()

  React.useEffect(() => {
    if (positions.length === 0) return
    try {
      const bounds = L.latLngBounds(positions)
      map.fitBounds(bounds, { padding, maxZoom })
    } catch (e) {
      // Ignore bounds errors
    }
  }, [positions.length, map, padding, maxZoom])

  return null
}

export { type LatLngExpression }
