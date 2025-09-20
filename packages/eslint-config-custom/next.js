module.exports = {
  extends: [
    "./index.js",
    "next/core-web-vitals",
    "plugin:react/recommended",
    "plugin:react-hooks/recommended",
    "plugin:jsx-a11y/recommended"
  ],
  plugins: [
    "react",
    "react-hooks",
    "jsx-a11y"
  ],
  settings: {
    react: {
      version: "detect"
    }
  },
  env: {
    browser: true,
    node: true,
    es6: true
  },
  rules: {
    // React specific rules
    "react/react-in-jsx-scope": "off", // Not needed in Next.js 13+
    "react/prop-types": "off", // We use TypeScript for type checking
    "react/no-unescaped-entities": "error",
    "react/jsx-key": "error",
    "react/jsx-no-duplicate-props": "error",
    "react/jsx-no-undef": "error",
    "react/jsx-uses-react": "off", // Not needed in Next.js 13+
    "react/jsx-uses-vars": "error",
    "react/no-danger": "warn",
    "react/no-deprecated": "error",
    "react/no-direct-mutation-state": "error",
    "react/no-find-dom-node": "error",
    "react/no-is-mounted": "error",
    "react/no-render-return-value": "error",
    "react/require-render-return": "error",
    "react/self-closing-comp": "error",

    // React Hooks rules
    "react-hooks/rules-of-hooks": "error",
    "react-hooks/exhaustive-deps": "warn",

    // Accessibility rules
    "jsx-a11y/alt-text": "error",
    "jsx-a11y/anchor-has-content": "error",
    "jsx-a11y/anchor-is-valid": "error",
    "jsx-a11y/aria-props": "error",
    "jsx-a11y/aria-proptypes": "error",
    "jsx-a11y/aria-unsupported-elements": "error",
    "jsx-a11y/click-events-have-key-events": "error",
    "jsx-a11y/heading-has-content": "error",
    "jsx-a11y/img-redundant-alt": "error",
    "jsx-a11y/no-access-key": "error",

    // Next.js specific rules
    "@next/next/no-img-element": "error",
    "@next/next/no-unwanted-polyfillio": "error",
    "@next/next/no-page-custom-font": "error",
    "@next/next/no-sync-scripts": "error",
    "@next/next/no-title-in-document-head": "error"
  },
  overrides: [
    {
      files: ["app/**/*.tsx", "pages/**/*.tsx"],
      rules: {
        "import/no-default-export": "off" // Next.js requires default exports for pages
      }
    },
    {
      files: ["*.stories.tsx", "*.stories.ts"],
      rules: {
        "import/no-default-export": "off" // Storybook requires default exports
      }
    }
  ]
};