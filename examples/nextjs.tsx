"use client"

import React, { useState, useEffect } from 'react';
import { getThumbmark } from "markplus";

function Fingerprint() {
    const [thumbmark, setThumbmark] = useState('');
  
    useEffect(() => {
      getThumbmark()
        .then((result) => {
          setThumbmark(result.thumbmark);
        })
        .catch((error) => {
          console.error('Error getting fingerprint:', error);
        });
    }, []);
    
    return (
      <>{thumbmark}</>
    );
  }

export default Fingerprint