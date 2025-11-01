/**
 * TLS/Cipher Suites Detection Component
 * 
 * Fingerprints browser's TLS/SSL capabilities including:
 * - Supported cipher suites (inferred from browser crypto capabilities)
 * - TLS protocol versions
 * - Supported cryptographic algorithms
 * - Secure context capabilities
 * - Certificate handling features
 */

import { componentInterface } from '../../factory';

interface CryptoCapabilities {
    subtle: boolean;
    algorithms: string[];
    keyUsages: string[];
    ellipticCurves: string[];
    hashAlgorithms: string[];
    signatureAlgorithms: string[];
}

interface TLSCapabilities {
    secureContext: boolean;
    protocols: {
        tls10: boolean;
        tls11: boolean;
        tls12: boolean;
        tls13: boolean;
    };
    features: string[];
}

export default async function getTLS(): Promise<componentInterface> {
    const cryptoCaps = await detectCryptoCapabilities();
    const tlsCaps = detectTLSCapabilities();
    const cipherSupport = await detectCipherSupport();
    
    return {
        secureContext: tlsCaps.secureContext,
        protocols: tlsCaps.protocols,
        crypto: {
            subtle: cryptoCaps.subtle,
            algorithms: cryptoCaps.algorithms,
            keyUsages: cryptoCaps.keyUsages,
            curves: cryptoCaps.ellipticCurves,
            hashes: cryptoCaps.hashAlgorithms,
            signatures: cryptoCaps.signatureAlgorithms,
        },
        cipherSupport: cipherSupport,
        features: tlsCaps.features,
        certFeatures: detectCertificateFeatures(),
    };
}

/**
 * Detects browser's cryptographic capabilities via Web Crypto API
 */
async function detectCryptoCapabilities(): Promise<CryptoCapabilities> {
    const caps: CryptoCapabilities = {
        subtle: false,
        algorithms: [],
        keyUsages: [],
        ellipticCurves: [],
        hashAlgorithms: [],
        signatureAlgorithms: [],
    };

    if (!window.crypto || !window.crypto.subtle) {
        return caps;
    }

    caps.subtle = true;

    // Test symmetric encryption algorithms
    const symmetricAlgos = [
        'AES-CBC', 'AES-CTR', 'AES-GCM', 'AES-KW'
    ];

    // Test asymmetric algorithms
    const asymmetricAlgos = [
        'RSA-OAEP', 'RSA-PSS', 'RSASSA-PKCS1-v1_5', 'ECDSA', 'ECDH'
    ];

    // Test all algorithms
    const allAlgos = [...symmetricAlgos, ...asymmetricAlgos, 'HMAC', 'PBKDF2', 'HKDF'];

    for (const algo of allAlgos) {
        try {
            // Try to generate a key with this algorithm
            let supported = false;
            
            if (symmetricAlgos.includes(algo)) {
                await window.crypto.subtle.generateKey(
                    { name: algo, length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                ).then(() => { supported = true; }).catch(() => {});
            } else if (algo === 'RSA-OAEP' || algo === 'RSA-PSS' || algo === 'RSASSA-PKCS1-v1_5') {
                await window.crypto.subtle.generateKey(
                    {
                        name: algo,
                        modulusLength: 2048,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: 'SHA-256'
                    },
                    false,
                    algo === 'RSA-OAEP' ? ['encrypt', 'decrypt'] : ['sign', 'verify']
                ).then(() => { supported = true; }).catch(() => {});
            } else if (algo === 'ECDSA' || algo === 'ECDH') {
                await window.crypto.subtle.generateKey(
                    {
                        name: algo,
                        namedCurve: 'P-256'
                    },
                    false,
                    algo === 'ECDSA' ? ['sign', 'verify'] : ['deriveKey', 'deriveBits']
                ).then(() => { supported = true; }).catch(() => {});
            }
            
            if (supported) {
                caps.algorithms.push(algo);
            }
        } catch (e) {
            // Algorithm not supported
        }
    }

    // Test elliptic curves
    const curves = ['P-256', 'P-384', 'P-521'];
    for (const curve of curves) {
        try {
            await window.crypto.subtle.generateKey(
                {
                    name: 'ECDSA',
                    namedCurve: curve
                },
                false,
                ['sign', 'verify']
            );
            caps.ellipticCurves.push(curve);
        } catch (e) {
            // Curve not supported
        }
    }

    // Test hash algorithms
    const hashes = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
    for (const hash of hashes) {
        try {
            await window.crypto.subtle.digest(hash, new Uint8Array([1, 2, 3]));
            caps.hashAlgorithms.push(hash);
        } catch (e) {
            // Hash not supported
        }
    }

    // Detect supported key usages
    const usages = ['encrypt', 'decrypt', 'sign', 'verify', 'deriveKey', 'deriveBits', 'wrapKey', 'unwrapKey'];
    caps.keyUsages = usages; // Most browsers support all of these

    // Detect signature algorithms (based on what we've tested)
    if (caps.algorithms.includes('ECDSA')) caps.signatureAlgorithms.push('ECDSA');
    if (caps.algorithms.includes('RSA-PSS')) caps.signatureAlgorithms.push('RSA-PSS');
    if (caps.algorithms.includes('RSASSA-PKCS1-v1_5')) caps.signatureAlgorithms.push('RSASSA-PKCS1-v1_5');

    return caps;
}

/**
 * Detects TLS protocol version support
 */
function detectTLSCapabilities(): TLSCapabilities {
    const caps: TLSCapabilities = {
        secureContext: window.isSecureContext || false,
        protocols: {
            tls10: false,
            tls11: false,
            tls12: true, // Modern browsers support at minimum TLS 1.2
            tls13: detectTLS13Support(),
        },
        features: [],
    };

    // Detect TLS-related features
    if ('crypto' in window && 'subtle' in window.crypto) {
        caps.features.push('WebCrypto');
    }

    if (window.isSecureContext) {
        caps.features.push('SecureContext');
    }

    if ('RTCPeerConnection' in window) {
        caps.features.push('DTLS'); // WebRTC implies DTLS support
    }

    // Check for modern TLS features
    if (typeof (window as any).PerformanceResourceTiming !== 'undefined') {
        caps.features.push('ResourceTiming');
    }

    if ('connection' in navigator) {
        caps.features.push('NetworkInformation');
    }

    // Detect HSTS support
    if (window.location.protocol === 'https:') {
        caps.features.push('HTTPS');
    }

    return caps;
}

/**
 * Detects TLS 1.3 support (inferentially)
 */
function detectTLS13Support(): boolean {
    // TLS 1.3 is supported in:
    // - Chrome 70+ (2018)
    // - Firefox 63+ (2018)
    // - Safari 12.1+ (2019)
    // - Edge 79+ (2020)
    
    const ua = navigator.userAgent;
    
    // Chrome/Chromium
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 70) return true;
    
    // Firefox
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 63) return true;
    
    // Safari
    const safariMatch = ua.match(/Version\/(\d+\.\d+)/);
    if (safariMatch && parseFloat(safariMatch[1]) >= 12.1) return true;
    
    // Edge Chromium
    const edgeMatch = ua.match(/Edg\/(\d+)/);
    if (edgeMatch && parseInt(edgeMatch[1]) >= 79) return true;
    
    return false;
}

/**
 * Detects supported cipher suites (inferred from crypto capabilities)
 */
async function detectCipherSupport(): Promise<string[]> {
    const ciphers: string[] = [];

    // Modern browsers support these cipher suite families
    // We can't directly query cipher suites in the browser, but we can infer support
    // based on cryptographic capabilities

    if (!window.crypto || !window.crypto.subtle) {
        return ciphers;
    }

    // AES-GCM based ciphers (TLS 1.2+)
    try {
        await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 128 },
            false,
            ['encrypt', 'decrypt']
        );
        ciphers.push('TLS_AES_128_GCM_SHA256');
        
        await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
        ciphers.push('TLS_AES_256_GCM_SHA384');
    } catch (e) { /* not supported */ }

    // ChaCha20-Poly1305 (modern browsers)
    // Can't directly test, but infer from browser version
    if (detectModernBrowser()) {
        ciphers.push('TLS_CHACHA20_POLY1305_SHA256');
    }

    // ECDHE support
    try {
        await window.crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            false,
            ['deriveKey']
        );
        ciphers.push('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256');
        ciphers.push('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384');
    } catch (e) { /* not supported */ }

    // RSA support
    try {
        await window.crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            false,
            ['encrypt', 'decrypt']
        );
        ciphers.push('TLS_RSA_WITH_AES_128_GCM_SHA256');
        ciphers.push('TLS_RSA_WITH_AES_256_GCM_SHA384');
    } catch (e) { /* not supported */ }

    return ciphers;
}

/**
 * Detects modern browser (likely supports latest TLS features)
 */
function detectModernBrowser(): boolean {
    const ua = navigator.userAgent;
    
    // Check for modern versions
    const chromeMatch = ua.match(/Chrome\/(\d+)/);
    if (chromeMatch && parseInt(chromeMatch[1]) >= 90) return true;
    
    const firefoxMatch = ua.match(/Firefox\/(\d+)/);
    if (firefoxMatch && parseInt(firefoxMatch[1]) >= 85) return true;
    
    const safariMatch = ua.match(/Version\/(\d+)/);
    if (safariMatch && parseInt(safariMatch[1]) >= 14) return true;
    
    return false;
}

/**
 * Detects certificate-related features
 */
function detectCertificateFeatures(): string[] {
    const features: string[] = [];

    // Check for Certificate Transparency
    if ('CertificateTransparency' in window || (window as any).trustedTypes) {
        features.push('CertificateTransparency');
    }

    // Check for SubjectAltName support (all modern browsers)
    if (window.isSecureContext) {
        features.push('SubjectAltName');
    }

    // Check for OCSP Stapling (inferred)
    if (window.location.protocol === 'https:') {
        features.push('OCSPStapling');
    }

    // Certificate pinning (via Expect-CT or similar)
    if ((navigator as any).connection && (navigator as any).connection.effectiveType) {
        features.push('NetworkInfo');
    }

    return features;
}

