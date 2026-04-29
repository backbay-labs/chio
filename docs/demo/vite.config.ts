import { defineConfig } from 'vite';

/**
 * docs-demo Vite config.
 *
 * - `base: './'` so the built artifact is portable: it works whether served
 *   from the GitHub Pages root or a sub-path. The Pages workflow uploads
 *   the `dist/` directory as the deploy artifact.
 * - `build.outDir = 'dist'` matches the artifact path the demo-pages workflow
 *   uploads.
 * - `build.assetsInlineLimit = 0` keeps the wasm artifact (when present)
 *   served as a fetched binary rather than inlined as a data URL, which
 *   `WebAssembly.instantiateStreaming` requires.
 */
export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    assetsInlineLimit: 0,
    target: 'es2022',
  },
  server: {
    port: 4173,
  },
});
