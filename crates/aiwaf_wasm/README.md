# aiwaf-wasm

Rust-powered WAF heuristics compiled to WebAssembly. Provides fast, deterministic
feature extraction and anomaly scoring in browsers and Node.

## Install

```bash
npm install aiwaf-wasm
```

## Usage (Node / Bundlers)

```js
import init, {
  validate_headers,
  validate_url,
  validate_content,
  validate_recent,
  AiwafIsolationForest,
} from "aiwaf-wasm";

// wasm-pack builds a default init() for the .wasm file
await init();

const headers = {
  "user-agent": "Mozilla/5.0",
  "accept": "text/html,application/xhtml+xml",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "gzip, deflate",
  "connection": "keep-alive",
};

const url = "https://example.com/login";
const content = "username=admin&password=...";

console.log(validate_headers(headers));
console.log(validate_url(url));
console.log(validate_content(content));
console.log(validate_recent([{ path: "/", status: 200 }]));

const model = new AiwafIsolationForest(100, 256, 0.5, 42);
model.fit([[0.1, 0.2, 0.3], [0.2, 0.1, 0.4]]);
console.log(model.anomaly_score([0.3, 0.2, 0.1]));
```

## Notes

- Browser usage requires bundler support for WASM (Vite, Webpack, etc.).
- The API mirrors the Python bindings for consistency.

## License

MIT
