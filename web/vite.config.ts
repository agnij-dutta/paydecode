import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Resolve the workspace library from source, so the web build never depends on
// packages/paydecode/dist being fresh (or on its .d.ts step succeeding).
const paydecodeSrc = fileURLToPath(new URL("../packages/paydecode/src/index.ts", import.meta.url));

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { paydecode: paydecodeSrc },
  },
});
