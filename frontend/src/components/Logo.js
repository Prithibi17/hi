import React from 'react';

const OneHiveLogo = ({ size = 'medium', showText = true }) => {
  const sizes = {
    small: { icon: 28, text: '1.1rem' },
    medium: { icon: 36, text: '1.4rem' },
    large: { icon: 48, text: '1.8rem' },
    xlarge: { icon: 64, text: '2.2rem' }
  };
  
  const { icon, text } = sizes[size];
  
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      {/* Bee Icon SVG */}
      <svg 
        width={icon} 
        height={icon} 
        viewBox="0 0 64 64" 
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Honeycomb base */}
        <path 
          d="M32 4L44 14V30L32 40L20 30V14L32 4Z" 
          fill="#E5A84B"
        />
        <path 
          d="M32 16L38 22V30L32 36L26 30V22L32 16Z" 
          fill="#D4A574"
        />
        {/* Bee stripes */}
        <ellipse cx="32" cy="28" rx="4" ry="8" fill="#2D3436"/>
        {/* Wings */}
        <ellipse cx="22" cy="22" rx="6" ry="4" fill="#FFFFFF" opacity="0.7" transform="rotate(-30 22 22)"/>
        <ellipse cx="42" cy="22" rx="6" ry="4" fill="#FFFFFF" opacity="0.7" transform="rotate(30 42 22)"/>
        {/* Eyes */}
        <circle cx="29" cy="26" r="1.5" fill="#2D3436"/>
        <circle cx="35" cy="26" r="1.5" fill="#2D3436"/>
      </svg>
      
      {showText && (
        <span style={{ 
          fontSize: text, 
          fontWeight: '700', 
          color: '#B8956A',
          letterSpacing: '-0.5px',
          fontFamily: "'Inter', sans-serif"
        }}>
          OneHive
        </span>
      )}
    </div>
  );
};

export default OneHiveLogo;
