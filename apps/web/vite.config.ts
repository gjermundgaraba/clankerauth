import { foldkit, foldkitViewIdentity } from "@foldkit/vite-plugin";
import { defineConfig } from "vite-plus";

const proxy = { target: "http://127.0.0.1:3001" };

export default defineConfig(({ command, mode }) => {
  const config = {
    plugins: mode === "test" ? [foldkitViewIdentity()] : foldkit(),
    test: {
      environment: "happy-dom",
      include: ["src/**/*.test.ts"],
      setupFiles: ["./src/vitest-setup.ts"],
      server: {
        deps: { inline: ["foldkit", "@foldkit/ui", "@gjermundgaraba-designs/pixel-paper"] },
      },
    },
  };

  if (command !== "serve") return config;

  return {
    ...config,
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
