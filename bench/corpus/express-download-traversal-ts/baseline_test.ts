declare const require: any;
declare const module: any;
declare const process: any;

const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const { createApp } = require(path.join(process.cwd(), "app.ts"));

function get(port: number, urlPath: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    http.get({ port, path: urlPath }, (res: any) => {
      const chunks: any[] = [];
      res.on("data", (chunk: any) => chunks.push(chunk));
      res.on("end", () => resolve({
        status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    }).on("error", reject);
  });
}

async function start(t: any, base: string): Promise<number> {
  await fs.mkdir(base, { recursive: true });
  const server = createApp(base).listen(0);
  await new Promise((resolve) => server.on("listening", resolve));
  t.after(() => server.close());
  return server.address().port;
}

test("serves a file inside the base directory", async (t: any) => {
  const base: string = await fs.mkdtemp(path.join(os.tmpdir(), "exhibit-a-"));
  await fs.writeFile(path.join(base, "hello.txt"), "hello");
  const port: number = await start(t, base);
  const reply = await get(port, "/download?name=hello.txt");
  assert.equal(reply.status, 200);
  assert.equal(reply.body, "hello");
});

test("a missing name answers 404", async (t: any) => {
  const base: string = await fs.mkdtemp(path.join(os.tmpdir(), "exhibit-a-"));
  const port: number = await start(t, base);
  const reply = await get(port, "/download?name=no-such-file.txt");
  assert.equal(reply.status, 404);
});

test("other methods are not served", async (t: any) => {
  const base: string = await fs.mkdtemp(path.join(os.tmpdir(), "exhibit-a-"));
  const port: number = await start(t, base);
  const status: number = await new Promise((resolve, reject) => {
    const req = http.request(
      { port, path: "/download?name=hello.txt", method: "POST" },
      (res: any) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      },
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(status, 404);
});
