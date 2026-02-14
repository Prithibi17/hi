import { useEffect, useRef, useState } from 'react';
import L from 'leaflet';

// Fix for default marker icons in Leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

const LocationMap = ({ 
  center = { lat: 19.0760, lng: 72.8777 }, 
  markerPosition, 
  onLocationSelect,
  height = '400px'
}) => {
  const mapRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const markerRef = useRef(null);
  const [mapError, setMapError] = useState(null);

  useEffect(() => {
    if (!mapRef.current) return;
    
    // Prevent double initialization
    if (mapInstanceRef.current) {
      return;
    }

    try {
      // Initialize map
      const map = L.map(mapRef.current, {
        center: [center.lat, center.lng],
        zoom: 13,
        zoomControl: true,
        scrollWheelZoom: true
      });

      // Add OpenStreetMap tiles
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 19
      }).addTo(map);

      mapInstanceRef.current = map;

      // Add click handler for location selection
      map.on('click', (e) => {
        const { lat, lng } = e.latlng;
        
        // Update or create marker
        if (markerRef.current) {
          markerRef.current.setLatLng([lat, lng]);
        } else {
          markerRef.current = L.marker([lat, lng], { draggable: true }).addTo(map);
          
          // Handle marker drag end
          markerRef.current.on('dragend', () => {
            const pos = markerRef.current.getLatLng();
            onLocationSelect && onLocationSelect({ lat: pos.lat, lng: pos.lng });
          });
        }
        
        onLocationSelect && onLocationSelect({ lat, lng });
      });

      // If there's an initial marker position, add marker
      if (markerPosition) {
        markerRef.current = L.marker([markerPosition.lat, markerPosition.lng], { draggable: true }).addTo(map);
        
        markerRef.current.on('dragend', () => {
          const pos = markerRef.current.getLatLng();
          onLocationSelect && onLocationSelect({ lat: pos.lat, lng: pos.lng });
        });
        
        map.setView([markerPosition.lat, markerPosition.lng], 15);
      }

    } catch (err) {
      console.error('Map initialization error:', err);
      setMapError('Failed to load map. Please try again.');
    }

    // Cleanup on unmount
    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
        markerRef.current = null;
      }
    };
  }, []);

  // Update marker when position changes externally
  useEffect(() => {
    if (!mapInstanceRef.current || !markerPosition) return;
    
    if (markerRef.current) {
      markerRef.current.setLatLng([markerPosition.lat, markerPosition.lng]);
    } else {
      markerRef.current = L.marker([markerPosition.lat, markerPosition.lng], { draggable: true }).addTo(mapInstanceRef.current);
      
      markerRef.current.on('dragend', () => {
        const pos = markerRef.current.getLatLng();
        onLocationSelect && onLocationSelect({ lat: pos.lat, lng: pos.lng });
      });
    }
    
    mapInstanceRef.current.setView([markerPosition.lat, markerPosition.lng], 15);
  }, [markerPosition, onLocationSelect]);

  if (mapError) {
    return (
      <div style={{ 
        height, 
        background: '#f5f5f5', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center',
        borderRadius: '8px',
        color: '#666',
        flexDirection: 'column',
        gap: '8px'
      }}>
        <i className="fas fa-exclamation-triangle" style={{ fontSize: '24px', color: '#f39c12' }}></i>
        <p>{mapError}</p>
      </div>
    );
  }

  return (
    <div 
      ref={mapRef} 
      style={{ 
        height, 
        width: '100%', 
        borderRadius: '8px',
        zIndex: 1
      }} 
    />
  );
};

// Reverse Geocoding function using Nominatim
export const reverseGeocode = async (lat, lng) => {
  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json`,
      {
        headers: {
          'User-Agent': 'OneHive/1.0'
        }
      }
    );
    
    if (!response.ok) {
      throw new Error('Reverse geocoding failed');
    }
    
    const data = await response.json();
    return data.display_name || null;
  } catch (err) {
    console.error('Reverse geocoding error:', err);
    return null;
  }
};

export default LocationMap;
