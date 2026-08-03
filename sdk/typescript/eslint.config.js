// @ts-check
import { sukka } from "eslint-config-sukka";
import { createTypeScriptImportResolver } from "eslint-import-resolver-typescript";

export default sukka(
  {
    ignores: {
      // Generated code is lint-exempt: protoc-gen-es owns its style.
      customGlobs: ["src/gen/**"],
    },
    // Biome owns formatting; no stylistic rules.
    stylistic: false,
    // npm-managed package inside a Rust repo — no pnpm workspace to lint.
    pnpm: false,
  },
  {
    settings: {
      "import-x/resolver-next": [
        createTypeScriptImportResolver({
          project: ["tsconfig.json"],
        }),
      ],
    },
  },
  {
    files: ["package.json"],
    rules: {
      // npm "files" negations must FOLLOW the pattern they negate
      // (last match wins); sorting would put "!dist/**" first and
      // re-include the excluded files.
      "jsonc/sort-array-values": "off",
    },
  },
  {
    files: ["src/sandbox.ts"],
    rules: {
      // ArcBox ⇄ Sandbox are a deliberately mutually recursive pair
      // (entry point mints handles, handle statics are sugar over the
      // entry point), so no source order can satisfy `classes: true`;
      // the references run at call time, never in the TDZ.
      "@typescript-eslint/no-use-before-define": [
        "error",
        { functions: false, classes: false, variables: true },
      ],
    },
  },
);
