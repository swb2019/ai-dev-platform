module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'subject-case': [2, 'never', ['sentence-case']],
    'type-enum': [2, 'always', ['feat', 'fix', 'ci', 'infra', 'security', 'chore', 'test', 'docs']]
  },
};
