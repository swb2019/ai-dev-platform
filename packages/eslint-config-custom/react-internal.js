module.exports = {
  extends: [
    "./index.js",
    "plugin:react/recommended",
    "plugin:react-hooks/recommended",
    "plugin:jsx-a11y/recommended",
  ],
  plugins: ["react", "react-hooks", "jsx-a11y"],
  settings: {
    react: {
      version: "detect",
    },
  },
  env: {
    browser: true,
    es6: true,
  },
  rules: {
    // React specific rules
    "react/react-in-jsx-scope": "error", // Required for React libraries
    "react/prop-types": "off", // We use TypeScript for type checking
    "react/no-unescaped-entities": "error",
    "react/jsx-key": "error",
    "react/jsx-no-duplicate-props": "error",
    "react/jsx-no-undef": "error",
    "react/jsx-uses-react": "error",
    "react/jsx-uses-vars": "error",
    "react/no-danger": "error",
    "react/no-deprecated": "error",
    "react/no-direct-mutation-state": "error",
    "react/no-find-dom-node": "error",
    "react/no-is-mounted": "error",
    "react/no-render-return-value": "error",
    "react/require-render-return": "error",
    "react/self-closing-comp": "error",
    "react/jsx-no-target-blank": "error",

    // React Hooks rules
    "react-hooks/rules-of-hooks": "error",
    "react-hooks/exhaustive-deps": "error",

    // Import/export rules for libraries
    "import/no-default-export": "error", // Prefer named exports for libraries
    "import/prefer-default-export": "off",
  },
};
