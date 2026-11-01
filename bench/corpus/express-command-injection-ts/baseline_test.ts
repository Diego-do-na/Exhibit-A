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

function post(port: number, urlPath: string, payload: any): Promise<{ status: number; body: string }> {
  const data: string = JSON.stringify(payload);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        port,
        path: urlPath,
        method: "POST",
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) },
      },
      (res: any) => {
        const chunks: any[] = [];
        res.on("data", (chunk: any) => chunks.push(chunk));
        res.on("end", () => resolve({
          status: res.statusCode,
          body: Buffer.concat(chunks).toString("utf8"),
        }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

async function start(t: any, base: string): Promise<number> {
  await fs.mkdir(base, { recursive: true });
  const server = createApp(base).listen(0);
  await new Promise((resolve) => server.on("listening", resolve));
  t.after(() => server.close());
  return server.address().port;
}

test("lists a file inside the base", async (t: any) => {
  const base: string = await fs.mkdtemp(path.join(os.tmpdir(), "exhibit-a-"));
  await fs.writeFile(path.join(base, "hello.txt"), "hello");
  const port: number = await start(t, base);
  const reply = await post(port, "/lookup", { name: "hello.txt" });
  assert.equal(reply.status, 200);
  assert.ok(reply.body.includes("hello.txt"));
});

test("a missing name lists nothing", async (t: any) => {
  const base: string = await fs.mkdtemp(path.join(os.tmpdir(), "exhibit-a-"));
  const port: number = await start(t, base);
  const reply = await post(port, "/lookup", { name: "no-such-file.txt" });
  assert.equal(reply.status, 200);
  assert.equal(reply.body, "");
});

test("a missing name field is rejected", async (t: any) => {
  const base: string = await fs.mkdtemp(path.join(os.tmpdir(), "exhibit-a-"));
  const port: number = await start(t, base);
  const reply = await post(port, "/lookup", {});
  assert.equal(reply.status, 400);
});
