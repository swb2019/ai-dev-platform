module.exports = {
  root: true,
  extends: [
    "@ai-dev-platform/eslint-config-custom",
    "plugin:import/recommended",
    "plugin:import/typescript",
  ],
  plugins: ["import"],
  parserOptions: {
    project: ["./tsconfig.eslint.json"],
    tsconfigRootDir: __dirname,
  },
  env: {
    node: true,
    jest: true,
  },
};
