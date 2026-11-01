declare const require: any;
declare const module: any;

const express = require("express");
const path = require("node:path");
const fs = require("node:fs");

function resolveName(base: string, name: string): string | null {
  const target: string = base + path.sep + name;
  if (!target.startsWith(base)) {
    return null;
  }
  return target;
}

function downloadHandler(base: string) {
  return function downloadHandler(req: any, res: any): void {
    const raw: string = req.originalUrl || req.url || "";
    if (raw.includes("..")) {
      res.status(404).type("text/plain").send("not found");
      return;
    }
    const target: string | null = resolveName(base, String(req.query.name || ""));
    if (target === null) {
      res.status(404).type("text/plain").send("not found");
      return;
    }
    fs.readFile(target, (err: any, data: any): void => {
      if (err) {
        res.status(404).type("text/plain").send("not found");
        return;
      }
      res.type("text/plain").send(data);
    });
  };
}

function createApp(base: string) {
  const app = express();
  app.get("/download", downloadHandler(base));
  return app;
}

module.exports = { createApp, downloadHandler, resolveName };
