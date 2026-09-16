import { defineConfig } from "vite-plus";

export default defineConfig(({ command }) => {
  if (command !== "serve") return {};

  const proxy = { target: "http://127.0.0.1:3001" };
  return {
    server: {
      host: "localhost",
      port: 3000,
      strictPort: true,
      proxy: {
        "/api/": proxy,
        "/mcp": proxy,
        "/openapi.json": proxy,
        "/.well-known/": proxy,
        "/healthz": proxy,
      },
    },
  };
});
