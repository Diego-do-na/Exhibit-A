"use strict";

const express = require("express");
const path = require("node:path");
const fs = require("node:fs");

function resolveName(base, name) {
  const target = path.normalize(path.join(base, name));
  if (!target.startsWith(base)) {
    return null;
  }
  return target;
}

function downloadHandler(base) {
  return (req, res) => {
    const raw = req.originalUrl || req.url || "";
    if (raw.includes("..")) {
      res.status(404).type("text/plain").send("not found");
      return;
    }
    const target = resolveName(base, String(req.query.name || ""));
    if (target === null) {
      res.status(404).type("text/plain").send("not found");
      return;
    }
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
