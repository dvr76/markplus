# markplus

A browser fingerprinting library for device identification and fraud detection.

This is a fork of [ThumbmarkJS](https://github.com/thumbmarkjs/thumbmarkjs) by Ilkka Peltola. Full credit to the original ThumbmarkJS project for the core fingerprinting technology. This is a simple side project that extends the MIT-licensed version with additional client-side detection capabilities.

## About

markplus is a client-side browser fingerprinting library that generates unique identifiers based on browser characteristics. It includes the original ThumbmarkJS components plus additional detection features:

- Audio fingerprinting
- Canvas fingerprinting
- WebGL fingerprinting
- Font detection and rendering
- Screen characteristics
- Browser permissions
- Available plugins
- Bot detection (automation frameworks)
- TLS/cipher suite capabilities
- HTTP protocol support (HTTP/2, HTTP/3)
- HTTP headers and client hints

## Getting Started

This library requires a browser environment to function.

### Building from Source

1. Clone this repository
2. Install dependencies:

```bash
npm install
```

3. Build the library:

```bash
npm run build
```

4. The compiled files will be in the `dist/` directory:
   - `dist/thumbmark.esm.js` - ES Module
   - `dist/thumbmark.cjs.js` - CommonJS
   - `dist/thumbmark.umd.js` - UMD (Universal Module Definition)

### Using in Browser

#### ES Module

```html
<script type="module">
  import { getThumbmark } from "./dist/thumbmark.esm.js";

  const result = await getThumbmark();
  console.log("Fingerprint:", result.thumbmark);
  console.log("Components:", result.components);
</script>
```

#### UMD (Classic script tag)

```html
<script src="./dist/thumbmark.umd.js"></script>
<script>
  ThumbmarkJS.getThumbmark().then((result) => {
    console.log("Fingerprint:", result.thumbmark);
    console.log("Components:", result.components);
  });
</script>
```

## Basic Usage

```javascript
import { getThumbmark } from "./dist/thumbmark.esm.js";

// Get complete fingerprint
const result = await getThumbmark();
console.log(result.thumbmark); // Unique hash
console.log(result.components); // All components

// With options
const result = await getThumbmark({
  exclude: ["audio", "math"], // Exclude specific components
  timeout: 5000, // Component timeout in ms
  performance: true, // Include timing data
});
```

## Options

| Option       | Type     | Default | Description                                  |
| ------------ | -------- | ------- | -------------------------------------------- |
| exclude      | string[] | []      | Exclude specific components from fingerprint |
| include      | string[] | []      | Only include specific components             |
| timeout      | number   | 5000    | Timeout for component resolution (ms)        |
| performance  | boolean  | false   | Include performance timing data              |
| experimental | boolean  | false   | Include experimental components              |

## Components

The fingerprint includes these components:

**Standard Components:**

- audio - Audio context fingerprint
- canvas - Canvas rendering fingerprint
- fonts - Available fonts and rendering
- hardware - Hardware concurrency and memory
- locales - Languages and timezone
- math - Math constant precision
- permissions - Browser permissions
- plugins - Available plugins
- screen - Screen dimensions and characteristics
- system - User agent and platform
- webgl - WebGL renderer information

**Extended Components:**

- tls - TLS/cipher suite support
- protocol - HTTP version and protocol support
- headers - HTTP headers and client hints

**Experimental Components:**

- webrtc - WebRTC capabilities
- mathml - MathML rendering

## Example

See the interactive example at `docs/example.html` for a complete working demonstration.

## License

MIT License - Same as the original ThumbmarkJS

This project is a fork of ThumbmarkJS (https://github.com/thumbmarkjs/thumbmarkjs) by Ilkka Peltola, licensed under the MIT License.

## Credits

Original ThumbmarkJS library: https://github.com/thumbmarkjs/thumbmarkjs
Author: Ilkka Peltola
Website: https://www.thumbmarkjs.com

This is a personal side project fork that extends the MIT-licensed version.

## Note

This library does not connect to any external services or APIs. All fingerprinting is performed client-side in the browser.
