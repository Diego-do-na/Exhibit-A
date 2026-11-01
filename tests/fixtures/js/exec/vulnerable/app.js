'use strict';

const { execSync } = require('node:child_process');

function runCommand(base, name) {
  return execSync(`ls ${base}/${name}`, { encoding: 'utf8' });
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
