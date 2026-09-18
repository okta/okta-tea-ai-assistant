'use strict';

const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  js.configs.recommended,
  // Source files
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...globals.node },
    },
    rules: {
      'no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      'eqeqeq': ['error', 'always'],
      'prefer-const': 'error',
      // single-line ifs without braces are acceptable (existing code style)
      'curly': ['error', 'multi-line'],
      'no-console': 'warn',
    },
  },
  // Test files — add Jest globals
  {
    files: ['tests/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...globals.node, ...globals.jest },
    },
    rules: {
      'no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      'eqeqeq': ['error', 'always'],
      'prefer-const': 'error',
      'curly': ['error', 'multi-line'],
      'no-console': 'warn',
    },
  },
  // Root config files use CommonJS (require / module.exports)
  {
    files: ['*.config.js', '*.config.cjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: { ...globals.node },
    },
  },
  {
    ignores: ['node_modules/**', 'coverage/**'],
  },
];
