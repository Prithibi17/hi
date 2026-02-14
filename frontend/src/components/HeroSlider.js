import React, { useState, useEffect } from 'react';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';
const UPLOADS_URL = process.env.REACT_APP_UPLOADS_URL || 'http://localhost:3001/uploads';

const HeroSlider = () => {
  const [slides, setSlides] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchSlides();
  }, []);

  useEffect(() => {
    // Auto-advance slides every 3 seconds
    if (slides.length > 1) {
      const interval = setInterval(() => {
        setCurrentIndex((prev) => (prev + 1) % slides.length);
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [slides.length]);

  const fetchSlides = async () => {
    try {
      const response = await fetch(`${API_URL}/hero-slider`);
      const data = await response.json();
      if (data.success && data.slides && data.slides.length > 0) {
        // Convert stored paths to full URLs
        const processedSlides = data.slides.map(slide => ({
          ...slide,
          image_url: slide.image_url?.startsWith('/uploads') 
            ? `${UPLOADS_URL}${slide.image_url.replace('/uploads', '')}`
            : slide.image_url
        }));
        setSlides(processedSlides);
      }
      setIsLoading(false);
    } catch (err) {
      console.error('Error fetching hero slider:', err);
      setError('Failed to load images');
      setIsLoading(false);
    }
  };

  // Show default content if no slides
  if (isLoading || slides.length === 0) {
    return null;
  }

  const currentSlide = slides[currentIndex];

  return (
    <div className="hero-slider">
      <div 
        className="hero-slider-image"
        style={{
          backgroundImage: `url(${currentSlide.image_url})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
        }}
      >
        {/* Overlay for text readability */}
        <div className="hero-slider-overlay"></div>
        
        {/* Slide Content */}
        <div className="hero-slider-content">
          {currentSlide.title && <h3>{currentSlide.title}</h3>}
          {currentSlide.subtitle && <p>{currentSlide.subtitle}</p>}
        </div>
        
        {/* Navigation Dots */}
        {slides.length > 1 && (
          <div className="hero-slider-dots">
            {slides.map((_, index) => (
              <button
                key={index}
                className={`hero-slider-dot ${index === currentIndex ? 'active' : ''}`}
                onClick={() => setCurrentIndex(index)}
                aria-label={`Go to slide ${index + 1}`}
              />
            ))}
          </div>
        )}
      </div>
      
      <style>{`
        .hero-slider {
          width: 100%;
          height: 100%;
          position: relative;
          border-radius: 24px;
          overflow: hidden;
        }
        
        .hero-slider-image {
          width: 100%;
          height: 300px;
          position: relative;
          transition: background-image 0.5s ease-in-out;
        }
        
        .hero-slider-overlay {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: linear-gradient(135deg, rgba(232, 201, 160, 0.3) 0%, rgba(212, 165, 116, 0.5) 100%);
          border-radius: 24px;
        }
        
        .hero-slider-content {
          position: absolute;
          bottom: 20px;
          left: 20px;
          right: 20px;
          z-index: 2;
          color: white;
          text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .hero-slider-content h3 {
          font-size: 1.5rem;
          font-weight: 600;
          margin-bottom: 8px;
          color: white;
        }
        
        .hero-slider-content p {
          font-size: 1rem;
          margin: 0;
          color: rgba(255, 255, 255, 0.9);
        }
        
        .hero-slider-dots {
          position: absolute;
          bottom: 12px;
          right: 20px;
          display: flex;
          gap: 8px;
          z-index: 3;
        }
        
        .hero-slider-dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          border: none;
          background: rgba(255, 255, 255, 0.5);
          cursor: pointer;
          transition: all 0.3s ease;
          padding: 0;
        }
        
        .hero-slider-dot.active {
          background: white;
          transform: scale(1.2);
        }
        
        .hero-slider-dot:hover {
          background: rgba(255, 255, 255, 0.8);
        }
      `}</style>
    </div>
  );
};

export default HeroSlider;
