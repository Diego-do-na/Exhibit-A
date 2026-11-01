'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

function runCommand(base, name) {
  return spawnSync('ls', [path.join(base, name)], { encoding: 'utf8' }).stdout || '';
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
