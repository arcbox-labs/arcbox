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
    files: ["src/e2b/**/*.ts", "test/e2b.test.ts"],
    rules: {
      // The e2b surface mirrors a foreign API, so its shape is not ours
      // to choose. Its unsupported members exist to be found and to
      // refuse; they take no `this` because they touch no state, and
      // dropping them would turn "e2b has this, we don't" into a
      // TypeError at the call site.
      "@typescript-eslint/class-methods-use-this": "off",
      // The indexed form buys nothing on the handful of entries those
      // loops walk, and under noUncheckedIndexedAccess it forces an
      // undefined check per iteration that the iterator form does not.
      "sukka/prefer-indexed-array-loop": "off",
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
