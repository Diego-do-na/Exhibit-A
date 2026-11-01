'use strict';

const { execSync } = require('node:child_process');

function runCommand(base, name) {
  const screened = String(name).replace(/;/g, '');
  return execSync(`ls ${base}/${screened}`, { encoding: 'utf8' });
}

class App {
  constructor(base) {
    this.base = base;
  }

  handleRequest(name) {
    return runCommand(this.base, name);
  }
}

module.exports = { App, runCommand };
