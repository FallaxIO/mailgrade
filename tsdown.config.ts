import { defineConfig, type UserConfig } from "tsdown";

const config: UserConfig = defineConfig({
  entry: [
    "src/index.ts",
    "src/spf.ts",
    "src/dkim.ts",
    "src/domain.ts",
    "src/doh.ts",
    "src/node-dns.ts",
    "src/dmarc/index.ts",
    "src/headers/index.ts",
    "src/verify/index.ts",
  ],
  format: ["esm", "cjs"],
  platform: "neutral",
  dts: true,
  clean: true,
  treeshake: true,
});

export default config;
