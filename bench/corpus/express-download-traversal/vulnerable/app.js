"use strict";

const express = require("express");
const path = require("node:path");
const fs = require("node:fs");

function resolveName(base, name) {
  return path.join(base, name);
}

function downloadHandler(base) {
  return function downloadHandler(req, res) {
    const target = resolveName(base, String(req.query.name || ""));
    fs.readFile(target, (err, data) => {
      if (err) {
        res.status(404).type("text/plain").send("not found");
        return;
      }
      res.type("text/plain").send(data);
    });
  };
}

function createApp(base) {
  const app = express();
  app.get("/download", downloadHandler(base));
  return app;
}

module.exports = { createApp, downloadHandler, resolveName };
