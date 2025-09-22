module.exports = {
  extends: ['@ai-dev-platform/eslint-config-custom/next'],
  parserOptions: {
    project: './tsconfig.json',
    tsconfigRootDir: __dirname,
  },
  settings: {
    import: {
      resolver: {
        typescript: {
          project: './tsconfig.json',
        },
      },
    },
  },
  rules: {
    '@next/next/no-html-link-for-pages': 'off',
  },
};
