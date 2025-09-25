const path = require("path");

module.exports = {
  root: true,
  extends: ["@ai-dev-platform/eslint-config-custom/next"],
  parserOptions: {
    project: [path.join(__dirname, "tsconfig.json")],
    tsconfigRootDir: __dirname,
  },
  settings: {
    import: {
      resolver: {
        typescript: {
          project: path.join(__dirname, "tsconfig.json"),
        },
      },
    },
  },
  rules: {
    "@next/next/no-html-link-for-pages": "off",
  },
};
