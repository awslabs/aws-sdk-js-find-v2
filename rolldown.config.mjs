import { defineConfig } from "rolldown";

export default defineConfig({
  output: {
    inlineDynamicImports: true,
    minify: true,
  },
});
