declare const require: any;
declare const module: any;

const express = require("express");
const { execFile } = require("node:child_process");
const path = require("node:path");

function runLookup(base: string, name: string): Promise<string> {
  return new Promise((resolve) => {
    execFile("ls", [path.join(base, name)], (err: any, stdout: any) => resolve(stdout || ""));
  });
}

function lookupHandler(base: string) {
  return async (req: any, res: any): Promise<void> => {
    const name: any = req.body ? req.body.name : undefined;
    if (typeof name !== "string") {
      res.status(400).type("text/plain").send("name is required");
      return;
    }
    const output: string = await runLookup(base, name);
    res.type("text/plain").send(output);
  };
}

function createApp(base: string) {
  const app = express();
  app.use(express.json());
  app.post("/lookup", lookupHandler(base));
  return app;
}

module.exports = { createApp, lookupHandler, runLookup };
