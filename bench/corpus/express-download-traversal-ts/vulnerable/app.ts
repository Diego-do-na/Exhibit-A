declare const require: any;
declare const module: any;

const express = require("express");
const path = require("node:path");
const fs = require("node:fs");

function resolveName(base: string, name: string): string {
  return path.join(base, name);
}

function downloadHandler(base: string) {
  return function downloadHandler(req: any, res: any): void {
    const target: string = resolveName(base, String(req.query.name || ""));
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
