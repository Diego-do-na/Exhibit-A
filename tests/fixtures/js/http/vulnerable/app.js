'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

function requestHandler(baseDir) {
  return function (req, res) {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const name = url.searchParams.get('name') || '';
    fs.readFile(path.join(baseDir, name), (err, data) => {
      if (err) {
        res.statusCode = 404;
        res.end('not found');
        return;
      }
      res.end(data);
    });
  };
}

function createApp(baseDir) {
  return http.createServer(requestHandler(baseDir));
}

module.exports = { createApp, requestHandler };
