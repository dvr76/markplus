/**
 * Protocol Extensions Detection Component
 * 
 * Detects browser's support for various protocol extensions and features:
 * - HTTP protocol versions (HTTP/1.1, HTTP/2, HTTP/3)
 * - ALPN (Application-Layer Protocol Negotiation)
 * - WebSocket protocols
 * - Server-Sent Events (SSE)
 * - WebRTC protocols
 * - Resource Hints (preconnect, prefetch, etc.)
 * - Early Hints (103 status)
 */

import { componentInterface } from '../../factory';

interface HTTPVersionSupport {
    http1: boolean;
    http2: boolean;
    http3: boolean;
    detection_method: string;
}

interface ProtocolExtensions {
    websocket: boolean;
    webrtc: boolean;
    sse: boolean;
    webTransport: boolean;
    webtorrent: boolean;
}

interface ResourceHints {
    preconnect: boolean;
    prefetch: boolean;
    prerender: boolean;
    preload: boolean;
    dns_prefetch: boolean;
    modulepreload: boolean;
}

export default async function getProtocol(): Promise<componentInterface> {
    const httpVersions = await detectHTTPVersions();
    const extensions = detectProtocolExtensions();
    const hints = detectResourceHints();
    const alpn = await detectALPN();
    
    return {
        http: httpVersions as any,
        alpn: alpn,
        extensions: extensions as any,
        resourceHints: hints as any,
        features: detectAdvancedFeatures(),
        headers: detectHeaderSupport(),
    };
}

/**
 * Detects HTTP protocol version support
 * Uses Performance API to analyze connection protocols
 */
async function detectHTTPVersions(): Promise<HTTPVersionSupport> {
    const support: HTTPVersionSupport = {
        http1: true, // All browsers support HTTP/1.1
        http2: false,
        http3: false,
        detection_method: 'performance-api',
    };

    // Method 1: Check via Performance Resource Timing API
    if (typeof PerformanceObserver !== 'undefined' && 'PerformanceResourceTiming' in window) {
        const entries = performance.getEntriesByType('navigation');
        
        if (entries.length > 0) {
            const navEntry = entries[0] as any;
            
            // Check nextHopProtocol if available
            if (navEntry.nextHopProtocol) {
                const protocol = navEntry.nextHopProtocol.toLowerCase();
                
                if (protocol.includes('h2') || protocol === 'http/2' || protocol === 'http/2.0') {
                    support.http2 = true;
                }
                
                if (protocol.includes('h3') || protocol === 'http/3' || protocol === 'http/3.0' || protocol === 'quic') {
                    support.http3 = true;
                }
            }
        }

        // Check resource timing entries for any HTTP/2 or HTTP/3 indicators
        const resources = performance.getEntriesByType('resource') as any[];
        for (const resource of resources) {
            if (resource.nextHopProtocol) {
                const protocol = resource.nextHopProtocol.toLowerCase();
                if (protocol.includes('h2')) support.http2 = true;
                if (protocol.includes('h3') || protocol.includes('quic')) support.http3 = true;
            }
        }
    }

    // Method 2: Infer from browser version if Performance API doesn't help
    if (!support.http2) {
        support.http2 = inferHTTP2Support();
    }
    
    if (!support.http3) {
        support.http3 = inferHTTP3Support();
    }

    return support;
}

/**
 * Infers HTTP/2 support from browser version
 */
function inferHTTP2Support(): boolean {
    const ua = navigator.userAgent;
    
    // Chrome 41+ (2015)
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 41) return true;
    
    // Firefox 36+ (2015)
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 36) return true;
    
    // Safari 9+ (2015)
    const safariMatch = ua.match(/Version\/(\d+)/);
    if (safariMatch && parseInt(safariMatch[1]) >= 9) return true;
    
    // Edge 12+ (2015)
    const edgeMatch = ua.match(/Edge\/(\d+)/);
    if (edgeMatch && parseInt(edgeMatch[1]) >= 12) return true;
    
    return false;
}

/**
 * Infers HTTP/3 (QUIC) support from browser version
 */
function inferHTTP3Support(): boolean {
    const ua = navigator.userAgent;
    
    // Chrome 87+ (2020) with QUIC enabled
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 87) return true;
    
    // Firefox 88+ (2021)
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 88) return true;
    
    // Safari 14+ (2020) experimental
    const safariMatch = ua.match(/Version\/(\d+)/);
    if (safariMatch && parseInt(safariMatch[1]) >= 14) return true;
    
    return false;
}

/**
 * Detects ALPN (Application-Layer Protocol Negotiation) support
 * ALPN allows negotiation of protocols like h2, h3, http/1.1
 */
async function detectALPN(): Promise<string[]> {
    const protocols: string[] = [];

    // Check what protocols the browser advertises support for
    // We can infer this from various APIs
    
    // HTTP/1.1 is always supported
    protocols.push('http/1.1');

    // Check HTTP/2
    const entries = performance.getEntriesByType('navigation');
    if (entries.length > 0) {
        const navEntry = entries[0] as any;
        if (navEntry.nextHopProtocol) {
            const proto = navEntry.nextHopProtocol.toLowerCase();
            if (!protocols.includes(proto)) {
                protocols.push(proto);
            }
        }
    }

    // If we detect HTTP/2 support, add it
    if (inferHTTP2Support() && !protocols.some(p => p.includes('h2'))) {
        protocols.push('h2');
    }

    // If we detect HTTP/3 support, add it
    if (inferHTTP3Support() && !protocols.some(p => p.includes('h3'))) {
        protocols.push('h3');
    }

    return protocols;
}

/**
 * Detects various protocol extensions support
 */
function detectProtocolExtensions(): ProtocolExtensions {
    return {
        websocket: 'WebSocket' in window,
        webrtc: 'RTCPeerConnection' in window || 
                'webkitRTCPeerConnection' in window || 
                'mozRTCPeerConnection' in window,
        sse: 'EventSource' in window,
        webTransport: 'WebTransport' in window,
        webtorrent: 'RTCPeerConnection' in window && 'WebSocket' in window,
    };
}

/**
 * Detects resource hint support
 */
function detectResourceHints(): ResourceHints {
    const hints: ResourceHints = {
        preconnect: false,
        prefetch: false,
        prerender: false,
        preload: false,
        dns_prefetch: false,
        modulepreload: false,
    };

    // Check by attempting to create link elements
    if (typeof document !== 'undefined') {
        const testLink = document.createElement('link');
        
        // Test each rel type
        const relSupport = testLink.relList;
        
        if (relSupport) {
            hints.preconnect = relSupport.supports ? relSupport.supports('preconnect') : true;
            hints.prefetch = relSupport.supports ? relSupport.supports('prefetch') : true;
            hints.prerender = relSupport.supports ? relSupport.supports('prerender') : false;
            hints.preload = relSupport.supports ? relSupport.supports('preload') : true;
            hints.dns_prefetch = relSupport.supports ? relSupport.supports('dns-prefetch') : true;
            hints.modulepreload = relSupport.supports ? relSupport.supports('modulepreload') : false;
        } else {
            // Fallback: assume modern browsers support most hints
            hints.preconnect = true;
            hints.prefetch = true;
            hints.dns_prefetch = true;
            hints.preload = true;
        }
    }

    return hints;
}

/**
 * Detects advanced protocol features
 */
function detectAdvancedFeatures(): string[] {
    const features: string[] = [];

    // Priority Hints (importance attribute)
    if (typeof HTMLImageElement !== 'undefined') {
        const testImg = document.createElement('img');
        if ('importance' in testImg) {
            features.push('priority-hints');
        }
    }

    // Early Hints (103 status) - can't directly detect, infer from browser
    if (inferEarlyHintsSupport()) {
        features.push('early-hints');
    }

    // Server Timing API
    if ('PerformanceServerTiming' in window) {
        features.push('server-timing');
    }

    // Navigation Timing
    if ('PerformanceNavigationTiming' in window) {
        features.push('navigation-timing');
    }

    // Resource Timing
    if ('PerformanceResourceTiming' in window) {
        features.push('resource-timing');
    }

    // Network Information API
    if ('connection' in navigator) {
        features.push('network-information');
    }

    // Reporting API
    if ('ReportingObserver' in window) {
        features.push('reporting-api');
    }

    // Feature Policy / Permissions Policy
    if ('featurePolicy' in document || 'permissionsPolicy' in document) {
        features.push('permissions-policy');
    }

    // Cross-Origin-Embedder-Policy (COEP)
    if (window.crossOriginIsolated !== undefined) {
        features.push('cross-origin-isolated');
    }

    // Fetch Priority
    if (typeof HTMLLinkElement !== 'undefined') {
        const testLink = document.createElement('link');
        if ('fetchPriority' in testLink) {
            features.push('fetch-priority');
        }
    }

    // Speculation Rules API
    if ('supports' in HTMLScriptElement && (HTMLScriptElement as any).supports) {
        try {
            if ((HTMLScriptElement as any).supports('speculationrules')) {
                features.push('speculation-rules');
            }
        } catch (e) { /* not supported */ }
    }

    return features;
}

/**
 * Infers Early Hints (103 status) support
 */
function inferEarlyHintsSupport(): boolean {
    const ua = navigator.userAgent;
    
    // Chrome 103+ (2022)
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 103) return true;
    
    // Firefox supports it experimentally
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 103) return true;
    
    return false;
}

/**
 * Detects HTTP header support and features
 */
function detectHeaderSupport(): string[] {
    const headers: string[] = [];

    // Accept-CH (Client Hints)
    if ((navigator as any).userAgentData) {
        headers.push('accept-ch');
    }

    // Accept-Encoding - all browsers support
    headers.push('accept-encoding');

    // Accept-Language - all browsers support
    headers.push('accept-language');

    // Check for specific header features via APIs
    
    // Save-Data
    if ('connection' in navigator && (navigator as any).connection) {
        if ('saveData' in (navigator as any).connection) {
            headers.push('save-data');
        }
    }

    // DNT (Do Not Track)
    if (navigator.doNotTrack !== undefined || (navigator as any).msDoNotTrack !== undefined) {
        headers.push('dnt');
    }

    // Sec-Fetch headers (modern browsers)
    if (detectModernBrowser()) {
        headers.push('sec-fetch-site');
        headers.push('sec-fetch-mode');
        headers.push('sec-fetch-dest');
        headers.push('sec-fetch-user');
    }

    // Sec-CH-UA (User Agent Client Hints)
    if ((navigator as any).userAgentData) {
        headers.push('sec-ch-ua');
        headers.push('sec-ch-ua-mobile');
        headers.push('sec-ch-ua-platform');
    }

    // Upgrade-Insecure-Requests
    if (window.location.protocol === 'https:') {
        headers.push('upgrade-insecure-requests');
    }

    return headers;
}

/**
 * Detects if browser is modern (Chromium 90+, Firefox 88+, Safari 14+)
 */
function detectModernBrowser(): boolean {
    const ua = navigator.userAgent;
    
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 90) return true;
    
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 88) return true;
    
    const safariMatch = ua.match(/Version\/(\d+)/);
    if (safariMatch && parseInt(safariMatch[1]) >= 14) return true;
    
    return false;
}

