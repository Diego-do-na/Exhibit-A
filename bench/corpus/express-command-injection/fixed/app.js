"use strict";

const express = require("express");
const { execFile } = require("node:child_process");
const path = require("node:path");

function runLookup(base, name) {
  return new Promise((resolve) => {
    execFile("ls", [path.join(base, name)], (err, stdout) => resolve(stdout || ""));
  });
}

function lookupHandler(base) {
  return async function lookupHandler(req, res) {
    const name = req.body ? req.body.name : undefined;
    if (typeof name !== "string") {
      res.status(400).type("text/plain").send("name is required");
      return;
    }
    const output = await runLookup(base, name);
    res.type("text/plain").send(output);
  };
}

function createApp(base) {
  const app = express();
  app.use(express.json());
  app.post("/lookup", lookupHandler(base));
  return app;
}

module.exports = { createApp, lookupHandler, runLookup };
