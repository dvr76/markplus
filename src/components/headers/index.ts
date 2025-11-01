/**
 * Enhanced HTTP Headers Detection Component
 * 
 * Comprehensive fingerprinting of HTTP headers and client hints:
 * - User-Agent Client Hints (UA-CH)
 * - Accept headers (encoding, language, types)
 * - Security headers (Sec-Fetch-*, Sec-CH-*)
 * - Network hints (Save-Data, ECT)
 * - Referrer policy
 * - Feature detection via headers
 */

import { componentInterface } from '../../factory';

interface ClientHints {
    supported: boolean;
    brands: any[];
    mobile: boolean;
    platform: string;
    architecture?: string;
    bitness?: string;
    model?: string;
    platformVersion?: string;
    fullVersionList?: any[];
    wow64?: boolean;
}

interface AcceptHeaders {
    language: string[];
    languageHeader: string;
    encoding: string[];
    contentTypes: {
        html: boolean;
        xml: boolean;
        json: boolean;
        webp: boolean;
        avif: boolean;
        jxl: boolean;
    };
}

interface SecurityHeaders {
    fetchSite: boolean;
    fetchMode: boolean;
    fetchDest: boolean;
    fetchUser: boolean;
    gpc: boolean; // Global Privacy Control
    dnt: string | null;
}

export default async function getHeaders(): Promise<componentInterface> {
    const clientHints = await detectClientHints();
    const acceptHeaders = detectAcceptHeaders();
    const securityHeaders = detectSecurityHeaders();
    const networkHints = detectNetworkHints();
    
    return {
        clientHints: clientHints as any,
        accept: acceptHeaders as any,
        security: securityHeaders as any,
        network: networkHints,
        features: detectHeaderFeatures(),
        policies: detectPolicies(),
    };
}

/**
 * Detects User-Agent Client Hints (UA-CH)
 * Modern replacement for User-Agent string
 */
async function detectClientHints(): Promise<ClientHints> {
    const hints: ClientHints = {
        supported: false,
        brands: [],
        mobile: false,
        platform: '',
    };

    // Check if User-Agent Client Hints API is available
    if ((navigator as any).userAgentData) {
        const uaData = (navigator as any).userAgentData;
        
        hints.supported = true;
        hints.brands = uaData.brands || [];
        hints.mobile = uaData.mobile || false;
        hints.platform = uaData.platform || '';

        // Try to get high entropy values
        try {
            const highEntropyValues = await uaData.getHighEntropyValues([
                'architecture',
                'bitness',
                'model',
                'platformVersion',
                'fullVersionList',
                'wow64'
            ]);

            hints.architecture = highEntropyValues.architecture;
            hints.bitness = highEntropyValues.bitness;
            hints.model = highEntropyValues.model;
            hints.platformVersion = highEntropyValues.platformVersion;
            hints.fullVersionList = highEntropyValues.fullVersionList;
            hints.wow64 = highEntropyValues.wow64;
        } catch (e) {
            // High entropy values not available (might require permissions policy)
        }
    }

    return hints;
}

/**
 * Detects Accept-* headers capabilities
 */
function detectAcceptHeaders(): AcceptHeaders {
    const headers: AcceptHeaders = {
        language: [],
        languageHeader: '',
        encoding: [],
        contentTypes: {
            html: true, // All browsers accept HTML
            xml: true,
            json: true,
            webp: false,
            avif: false,
            jxl: false,
        },
    };

    // Accept-Language
    if (navigator.languages) {
        headers.language = Array.from(navigator.languages);
    } else if (navigator.language) {
        headers.language = [navigator.language];
    }

    // Construct Accept-Language header format
    headers.languageHeader = constructAcceptLanguageHeader(headers.language);

    // Accept-Encoding (inferred - browsers typically support these)
    headers.encoding = ['gzip', 'deflate', 'br']; // Brotli is widely supported now

    // Accept content types - detect image format support
    headers.contentTypes.webp = detectImageFormatSupport('webp');
    headers.contentTypes.avif = detectImageFormatSupport('avif');
    headers.contentTypes.jxl = detectImageFormatSupport('jxl');

    return headers;
}

/**
 * Constructs Accept-Language header with quality values
 */
function constructAcceptLanguageHeader(languages: string[]): string {
    if (languages.length === 0) return '';
    
    // First language gets q=1.0 (implicit), others get decreasing quality values
    return languages.map((lang, index) => {
        if (index === 0) return lang;
        const quality = Math.max(0.1, 1.0 - (index * 0.1)).toFixed(1);
        return `${lang};q=${quality}`;
    }).join(', ');
}

/**
 * Detects image format support via canvas
 */
function detectImageFormatSupport(format: string): boolean {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        
        const mimeType = `image/${format}`;
        const dataUrl = canvas.toDataURL(mimeType);
        
        // If the browser doesn't support the format, it falls back to image/png
        return dataUrl.startsWith(`data:${mimeType}`);
    } catch (e) {
        return false;
    }
}

/**
 * Detects Sec-Fetch-* and security-related headers
 */
function detectSecurityHeaders(): SecurityHeaders {
    return {
        fetchSite: detectSecFetchSupport(),
        fetchMode: detectSecFetchSupport(),
        fetchDest: detectSecFetchSupport(),
        fetchUser: detectSecFetchSupport(),
        gpc: detectGlobalPrivacyControl(),
        dnt: detectDoNotTrack(),
    };
}

/**
 * Detects Sec-Fetch-* headers support (Chromium 76+, Firefox 90+)
 */
function detectSecFetchSupport(): boolean {
    const ua = navigator.userAgent;
    
    // Chrome/Edge 76+
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 76) return true;
    
    // Firefox 90+
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 90) return true;
    
    return false;
}

/**
 * Detects Global Privacy Control (GPC) support
 */
function detectGlobalPrivacyControl(): boolean {
    return (navigator as any).globalPrivacyControl === true;
}

/**
 * Detects Do Not Track (DNT) setting
 */
function detectDoNotTrack(): string | null {
    if (navigator.doNotTrack !== undefined) {
        return navigator.doNotTrack;
    }
    if ((window as any).doNotTrack !== undefined) {
        return (window as any).doNotTrack;
    }
    if ((navigator as any).msDoNotTrack !== undefined) {
        return (navigator as any).msDoNotTrack;
    }
    return null;
}

/**
 * Detects network-related hints (Save-Data, ECT, RTT)
 */
function detectNetworkHints(): componentInterface {
    const hints: componentInterface = {
        supported: false,
    };

    if ('connection' in navigator) {
        const connection = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection;
        
        if (connection) {
            hints.supported = true;
            hints.saveData = connection.saveData || false;
            hints.effectiveType = connection.effectiveType || null; // 4g, 3g, 2g, slow-2g
            hints.downlink = connection.downlink || null; // Mbps
            hints.rtt = connection.rtt || null; // Round-trip time in ms
            hints.downlinkMax = connection.downlinkMax || null;
            hints.type = connection.type || null; // wifi, cellular, ethernet, etc.
        }
    }

    return hints;
}

/**
 * Detects header-related features and capabilities
 */
function detectHeaderFeatures(): string[] {
    const features: string[] = [];

    // User-Agent Client Hints
    if ((navigator as any).userAgentData) {
        features.push('ua-client-hints');
    }

    // Network Information API
    if ('connection' in navigator) {
        features.push('network-information');
    }

    // Permissions Policy
    if ('permissionsPolicy' in document || 'featurePolicy' in document) {
        features.push('permissions-policy');
    }

    // Critical-CH (Critical Client Hints)
    if ((navigator as any).userAgentData && 'getHighEntropyValues' in (navigator as any).userAgentData) {
        features.push('critical-ch');
    }

    // Accept-CH-Lifetime (deprecated but still detectable)
    // Modern browsers use Permissions-Policy instead

    // Viewport meta tag support
    if (typeof document !== 'undefined') {
        const viewportMeta = document.querySelector('meta[name="viewport"]');
        if (viewportMeta) {
            features.push('viewport-meta');
        }
    }

    // Device-Memory API
    if ((navigator as any).deviceMemory !== undefined) {
        features.push('device-memory');
    }

    // Referrer-Policy support
    if (typeof document !== 'undefined' && 'referrerPolicy' in document) {
        features.push('referrer-policy');
    }

    return features;
}

/**
 * Detects various security and privacy policies
 */
function detectPolicies(): componentInterface {
    const policies: componentInterface = {
        referrer: (document as any).referrerPolicy || 'default',
        crossOriginIsolated: window.crossOriginIsolated || false,
    };

    // Feature Policy / Permissions Policy
    if ('permissionsPolicy' in document) {
        const permPolicy = (document as any).permissionsPolicy;
        policies.permissionsPolicy = true;
        
        // Try to get allowed features
        try {
            const allowedFeatures: string[] = [];
            const testFeatures = [
                'camera', 'microphone', 'geolocation', 'payment',
                'usb', 'accelerometer', 'gyroscope', 'magnetometer'
            ];
            
            for (const feature of testFeatures) {
                try {
                    if (permPolicy.allowedFeatures && permPolicy.allowedFeatures().includes(feature)) {
                        allowedFeatures.push(feature);
                    } else if (permPolicy.getAllowlistForFeature) {
                        const allowlist = permPolicy.getAllowlistForFeature(feature);
                        if (allowlist && allowlist.length > 0) {
                            allowedFeatures.push(feature);
                        }
                    }
                } catch (e) { /* feature not recognized */ }
            }
            
            policies.allowedFeatures = allowedFeatures;
        } catch (e) { /* unable to query */ }
    } else if ('featurePolicy' in document) {
        policies.featurePolicy = true;
    }

    // COOP (Cross-Origin-Opener-Policy) detection
    // Can't directly detect, but we can detect its effects
    if (window.crossOriginIsolated) {
        policies.coop = 'enabled';
    }

    // COEP (Cross-Origin-Embedder-Policy) detection
    if (window.crossOriginIsolated) {
        policies.coep = 'enabled';
    }

    // Trusted Types
    if ((window as any).trustedTypes) {
        policies.trustedTypes = true;
    }

    // Content Security Policy (CSP) - can't directly query, but can detect violations
    // We can check if we're in a secure context which often implies CSP
    policies.secureContext = window.isSecureContext;

    return policies;
}

