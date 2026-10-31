import simpleImportSort from "eslint-plugin-simple-import-sort";
import * as tseslint from "typescript-eslint";

export default [
  { ignores: ["dist/", "coverage/"] },
  ...tseslint.configs.recommended,

  {
    files: ["**/*.{js,ts}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
    },
    plugins: {
      "simple-import-sort": simpleImportSort,
    },
    rules: {
      "simple-import-sort/imports": "error",
      "simple-import-sort/exports": "error",
      "@typescript-eslint/no-non-null-assertion": "warn",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],

      "no-delete-var": "off",
    },
  },
];
