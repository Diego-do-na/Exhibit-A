'use strict';

const fs = require('node:fs');
const path = require('node:path');

function readFile(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

class App {
  constructor(baseDir) {
    this.baseDir = baseDir;
    this.routes = {};
  }

  route(routePath, view) {
    this.routes[routePath] = view;
    return view;
  }

  handleRequest(method, routePath, query) {
    const view = this.routes[routePath];
    if (method !== 'GET' || view == null) {
      return { status: 404, body: 'not found' };
    }
    return view(query || {});
  }
}

function createApp(baseDir) {
  const app = new App(baseDir);
  app.route('/download', function download(query) {
    const name = (query && query.name) || '';
    const base = fs.realpathSync(app.baseDir);
    let target;
    try {
      target = fs.realpathSync(path.join(base, name));
    } catch (err) {
      return { status: 404, body: 'not found' };
    }
    if (target !== base && !target.startsWith(base + path.sep)) {
      return { status: 403, body: 'forbidden' };
    }
    return { status: 200, body: readFile(target) };
  });
  return app;
}

module.exports = { App, createApp, readFile };
