import { defineConfig } from "vite-plus";

export default defineConfig({
  test: {
    include: ["test/**/*.ts", "test/**/*.test.ts", "test/**/*.test-d.ts"],
  },
  run: {
    tasks: {
      // build: {
      //   command: "rm -rf dist && tsc -p ./tsconfig.build.json",
      //   input: ["src/**/*.ts", "!**/dist/**/*", "!**/node_modules/**/*"],
      // },

      test: {
        command: "vp test",
        input: ["test/**/*.ts", "!**/dist/**/*"],
      },
    },
  },
});
