'use strict';

module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  collectCoverageFrom: ['src/tools/**/*.js', '!src/tools/auth.js'],
  coverageThreshold: {
    global: { lines: 70 },
  },
};
