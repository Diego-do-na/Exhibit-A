/**
 * Exhibit A Node oracle preload (CommonJS, no dependencies).
 *
 * Loaded with `node --require` before any application or test code. Wraps
 * filesystem and process-creation APIs, captures a V8 CallSite stack, and
 * writes HMAC-signed JSONL events the host judge already understands.
 *
 * Isolated and resource-limited, never "100% safe". A missing or tampered
 * channel produces no proof.
 */
'use strict';

const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const { AsyncLocalStorage } = require('node:async_hooks');
const Module = require('node:module');
const vm = require('node:vm');
const http = require('node:http');
const https = require('node:https');
const { EventEmitter } = require('node:events');

const ENV_CANARY = 'EXHIBIT_A_CANARY';
const ENV_EVENTS = 'EXHIBIT_A_EVENTS';
const ENV_MARKER = 'EXHIBIT_A_CANARY_MARKER';
const ENV_ALLOWED = 'EXHIBIT_A_ALLOWED_DIR';
const KEY_MAGIC = 'EXHIBIT-A-KEY ';
const MANIFEST_MAGIC = 'EXHIBIT-A-MANIFEST ';
const KEY_BYTES = 32;
const MAX_STDIN = 64 * 1024 * 1024;
const MAX_FRAMES = 200;
const MAX_FIELD = 512;
const MAX_REQUESTED = 4096;
const MAX_COMMAND = 4096;
const MAX_SCANNED = 1 << 16;
const SYMLINK_SLACK_MS = 2000;
const PLUGIN_FILE = __filename;

const SINK_NAMES = new Set([
  'exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork',
  'run', 'system',
]);
const SENSITIVE_ENV = new Set(['PATH', 'IFS', 'ENV', 'BASH_ENV', 'CDPATH', 'SHELL', 'GLOBIGNORE']);
const SENSITIVE_PREFIXES = ['LD_', 'DYLD_', 'NODE_OPTIONS', 'NODE_', 'PYTHON', 'BASH_FUNC_'];

const orig = {
  openSync: fs.openSync.bind(fs),
  closeSync: fs.closeSync.bind(fs),
  readSync: fs.readSync.bind(fs),
  readFileSync: fs.readFileSync.bind(fs),
  writeFileSync: fs.writeFileSync.bind(fs),
  mkdirSync: fs.mkdirSync.bind(fs),
  realpathSync: fs.realpathSync.bind(fs),
  lstatSync: fs.lstatSync.bind(fs),
  statSync: fs.statSync.bind(fs),
  readlinkSync: fs.readlinkSync.bind(fs),
  existsSync: fs.existsSync.bind(fs),
  open: fs.open.bind(fs),
  readFile: fs.readFile.bind(fs),
  createReadStream: fs.createReadStream.bind(fs),
  opendirSync: fs.opendirSync.bind(fs),
  opendir: fs.opendir.bind(fs),
  read: fs.read.bind(fs),
  promisesOpen: fsp.open.bind(fsp),
  promisesReadFile: fsp.readFile.bind(fsp),
  promisesOpendir: fsp.opendir.bind(fsp),
  exec: childProcess.exec.bind(childProcess),
  execSync: childProcess.execSync.bind(childProcess),
  spawn: childProcess.spawn.bind(childProcess),
  spawnSync: childProcess.spawnSync.bind(childProcess),
  execFile: childProcess.execFile.bind(childProcess),
  execFileSync: childProcess.execFileSync.bind(childProcess),
  fork: childProcess.fork.bind(childProcess),
  chdir: process.chdir.bind(process),
  binding: typeof process.binding === 'function' ? process.binding.bind(process) : null,
  linkedBinding: typeof process._linkedBinding === 'function' ? process._linkedBinding.bind(process) : null,
  createRequire: Module.createRequire.bind(Module),
  load: Module._load,
  vmCreateContext: vm.createContext.bind(vm),
  vmRunInContext: vm.runInContext.bind(vm),
  vmRunInNewContext: vm.runInNewContext.bind(vm),
  vmRunInThisContext: vm.runInThisContext.bind(vm),
  emit: EventEmitter.prototype.emit,
};

let installed = false;
const als = new AsyncLocalStorage();
const sinceMs = Date.now();

function canonical(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonical).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  const parts = [];
  for (const key of keys) {
    parts.push(JSON.stringify(key) + ':' + canonical(value[key]));
  }
  return '{' + parts.join(',') + '}';
}

function signedBytes(seq, body) {
  return Buffer.from(String(seq) + '\n' + canonical(body), 'ascii');
}

function signEvent(key, seq, body) {
  const sig = key
    ? crypto.createHmac('sha256', key).update(signedBytes(seq, body)).digest('hex')
    : '';
  return { body: body, seq: seq, sig: sig };
}

function parseChannel(data) {
  if (!data || !data.length || data[data.length - 1] !== 0x0a) {
    return [null, null];
  }
  const text = data.toString('ascii');
  const lines = text.slice(0, -1).split('\n');
  if (lines.length > 2 || !lines[0].startsWith(KEY_MAGIC)) {
    return [null, null];
  }
  let key;
  try {
    key = Buffer.from(lines[0].slice(KEY_MAGIC.length), 'hex');
  } catch (err) {
    return [null, null];
  }
  if (key.length !== KEY_BYTES) {
    return [null, null];
  }
  if (lines.length === 1) {
    return [key, null];
  }
  if (!lines[1].startsWith(MANIFEST_MAGIC)) {
    return [null, null];
  }
  try {
    const app = JSON.parse(lines[1].slice(MANIFEST_MAGIC.length));
    if (
      !app || typeof app !== 'object' ||
      typeof app.root !== 'string' || !app.root.startsWith('/') ||
      !app.files || typeof app.files !== 'object'
    ) {
      return [null, null];
    }
    return [key, app];
  } catch (err) {
    return [null, null];
  }
}

function readStdin() {
  const chunks = [];
  const buf = Buffer.alloc(65536);
  let total = 0;
  for (;;) {
    let n;
    try {
      n = orig.readSync(0, buf, 0, buf.length, null);
    } catch (err) {
      break;
    }
    if (!n) {
      break;
    }
    chunks.push(Buffer.from(buf.subarray(0, n)));
    total += n;
    if (total > MAX_STDIN) {
      break;
    }
  }
  return Buffer.concat(chunks);
}

function sha256File(filePath) {
  const fd = orig.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const hash = crypto.createHash('sha256');
    const buf = Buffer.alloc(1 << 16);
    for (;;) {
      const n = orig.readSync(fd, buf, 0, buf.length, null);
      if (!n) {
        break;
      }
      hash.update(buf.subarray(0, n));
    }
    return hash.digest('hex');
  } finally {
    orig.closeSync(fd);
  }
}

function captureSites() {
  const err = {};
  const prepared = Error.prepareStackTrace;
  try {
    Error.prepareStackTrace = function prepare(_error, sites) {
      return sites;
    };
    Error.captureStackTrace(err, captureSites);
    // Force the getter so prepareStackTrace runs.
    return err.stack || [];
  } finally {
    Error.prepareStackTrace = prepared;
  }
}

function relativeToRoot(file, root) {
  if (!root || !file) {
    return null;
  }
  const base = root.endsWith('/') ? root.slice(0, -1) : root;
  if (file === base) {
    return null;
  }
  if (!file.startsWith(base + '/')) {
    return null;
  }
  return file.slice(base.length + 1);
}

function isDigest(value) {
  return typeof value === 'string' && value.length === 64 && /^[0-9a-f]+$/.test(value);
}

function accessOf(flags, mode) {
  if (typeof mode === 'string') {
    // fs.open modes vs encodings ('utf8') passed as readFile's second argument.
    if (/^[rwa]/.test(mode)) {
      if (mode.includes('+')) {
        return 'read_write';
      }
      if (mode.startsWith('r')) {
        return 'read';
      }
      return 'write';
    }
    return 'read';
  }
  if (typeof flags !== 'number') {
    return 'unknown';
  }
  const O_RDONLY = fs.constants.O_RDONLY;
  const O_WRONLY = fs.constants.O_WRONLY;
  const O_RDWR = fs.constants.O_RDWR;
  const O_ACCMODE = fs.constants.O_ACCMODE != null
    ? fs.constants.O_ACCMODE
    : (O_RDONLY | O_WRONLY | O_RDWR);
  const accmode = flags & O_ACCMODE;
  const read = accmode === O_RDONLY || accmode === O_RDWR;
  const write = accmode === O_WRONLY || accmode === O_RDWR ||
    Boolean(flags & (fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND));
  if (read && write) {
    return 'read_write';
  }
  if (write) {
    return 'write';
  }
  if (read) {
    return 'read';
  }
  return 'unknown';
}

function viaSymlink(absolute) {
  if (!absolute) {
    return { via_symlink: false };
  }
  let here = absolute;
  for (let hop = 0; hop < 40; hop += 1) {
    try {
      const st = orig.lstatSync(here);
      if (st.isSymbolicLink()) {
        const ageOk = (st.ctimeMs >= sinceMs - SYMLINK_SLACK_MS) ||
          (st.mtimeMs >= sinceMs - SYMLINK_SLACK_MS);
        if (ageOk) {
          let target = '';
          try {
            target = orig.readlinkSync(here);
          } catch (err) {
            target = '';
          }
          return {
            via_symlink: true,
            symlink: String(here).slice(0, MAX_FIELD),
            symlink_target: String(target).slice(0, MAX_FIELD),
          };
        }
      }
    } catch (err) {
      // Missing component: keep walking up.
    }
    const parent = path.dirname(here);
    if (parent === here) {
      break;
    }
    here = parent;
  }
  return { via_symlink: false };
}

function commandParts(value, out) {
  if (value == null) {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      commandParts(item, out);
    }
    return;
  }
  if (typeof value === 'string') {
    out.push(value);
  }
}

function namesCanary(parts, cwd, canaryPath) {
  const name = path.basename(canaryPath);
  const suffix = path.basename(path.dirname(canaryPath)) + '/' + name;
  const split = /[\s;&|<>`$()]+/;
  for (const part of parts) {
    const words = String(part).slice(0, MAX_SCANNED).split(split);
    for (const word of words) {
      if (!word || word.indexOf(name) === -1) {
        continue;
      }
      try {
        if (word.startsWith('/')) {
          if (orig.realpathSync(word) === canaryPath) {
            return true;
          }
        } else {
          const joined = path.resolve(cwd || process.cwd(), word);
          if (orig.realpathSync(joined) === canaryPath) {
            return true;
          }
          const norm = path.normalize(word);
          if (norm === suffix || norm.endsWith('/' + suffix)) {
            return true;
          }
        }
      } catch (err) {
        const norm = path.normalize(word);
        if (norm === suffix || norm.endsWith('/' + suffix) || word === canaryPath) {
          return true;
        }
      }
    }
  }
  return false;
}

function freezeProp(obj, name, value, enumerable) {
  try {
    Object.defineProperty(obj, name, {
      value: value,
      writable: false,
      configurable: false,
      enumerable: enumerable !== false,
    });
  } catch (err) {
    try {
      obj[name] = value;
    } catch (err2) {
      // Best effort: a later freeze still trips casual reassignment.
    }
  }
}

function install() {
  if (installed) {
    return;
  }
  installed = true;

  const canaryEnv = process.env[ENV_CANARY];
  const eventsPath = process.env[ENV_EVENTS];
  const markerEnv = process.env[ENV_MARKER];
  const allowedDir = process.env[ENV_ALLOWED];
  if (!canaryEnv || !eventsPath) {
    return;
  }

  const [key, app] = parseChannel(readStdin());
  const appRoot = app && typeof app.root === 'string' ? orig.realpathSync(app.root) : null;
  const manifestFiles = (app && app.files) || {};

  let canaryReal;
  let canaryId = { dev: -1, ino: -1 };
  try {
    canaryReal = orig.realpathSync(canaryEnv);
    const st = orig.statSync(canaryReal);
    canaryId = { dev: st.dev, ino: st.ino };
  } catch (err) {
    canaryReal = path.resolve(canaryEnv);
  }
  let markerReal = null;
  if (markerEnv) {
    markerReal = path.join(path.dirname(canaryReal), path.basename(markerEnv));
  }

  if (allowedDir) {
    try {
      orig.mkdirSync(allowedDir, { recursive: true });
      const pub = path.join(allowedDir, 'public.txt');
      if (!orig.existsSync(pub)) {
        orig.writeFileSync(pub, 'public file\n');
      }
    } catch (err) {
      // Layout is best-effort; a missing public file is not a proof.
    }
  }

  let eventsFd;
  try {
    eventsFd = orig.openSync(eventsPath, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT, 0o600);
  } catch (err) {
    return;
  }
  let seq = 0;

  function emit(record) {
    const line = JSON.stringify(signEvent(key, seq, record)) + '\n';
    seq += 1;
    orig.writeFileSync(eventsFd, line);
  }

  function admit(file, site) {
    const out = {
      file: file,
      function: (site && (site.getFunctionName() || site.getMethodName())) || '<anonymous>',
      qualname: (site && (site.getFunctionName() || site.getMethodName())) || '<anonymous>',
      line: (site && site.getLineNumber && site.getLineNumber()) || 1,
    };
    if (site && site.isEval && site.isEval()) {
      if (appRoot && file.startsWith(appRoot)) {
        out.admitted = false;
        out.admission = 'callSite.isEval()';
      }
      return out;
    }
    const rel = relativeToRoot(file, appRoot);
    if (rel == null) {
      return out;
    }
    const digest = manifestFiles[rel];
    if (!isDigest(digest)) {
      out.admitted = false;
      out.admission = 'file not in the staged app manifest';
      return out;
    }
    try {
      const current = sha256File(file);
      if (current !== digest) {
        out.admitted = false;
        out.admission = 'file content changed since staging';
        return out;
      }
    } catch (err) {
      out.admitted = false;
      out.admission = 'file unreadable at admission';
      return out;
    }
    out.admitted = true;
    return out;
  }

  function siteFile(site) {
    const name = site && site.getFileName && site.getFileName();
    if (!name || name.startsWith('node:') || name.startsWith('internal/')) {
      return name || '';
    }
    try {
      return orig.realpathSync(name);
    } catch (err) {
      return path.resolve(name);
    }
  }

  function captureFrames() {
    const sites = captureSites();
    const innerFirst = [];
    for (const site of sites) {
      if (!site) {
        continue;
      }
      const file = siteFile(site);
      if (!file || file === PLUGIN_FILE || file.indexOf('oracle.cjs') !== -1) {
        continue;
      }
      if (site.isNative && site.isNative()) {
        continue;
      }
      innerFirst.push(admit(file, site));
      if (innerFirst.length >= MAX_FRAMES) {
        break;
      }
    }
    innerFirst.reverse();
    return innerFirst;
  }

  function isTestFile(file) {
    const rel = relativeToRoot(file, appRoot);
    if (rel == null) {
      return false;
    }
    return !isDigest(manifestFiles[rel]);
  }

  function isHttpServer(server) {
    try {
      return server instanceof http.Server || server instanceof https.Server;
    } catch (err) {
      return false;
    }
  }

  function isPublicInterface() {
    const store = als.getStore();
    return Boolean(store && store.publicInterface);
  }

  function logicalStack() {
    const physical = captureFrames();
    const store = als.getStore();
    if (physical.some(function hasTest(frame) { return isTestFile(frame.file); })) {
      return physical;
    }
    if (!store || !Array.isArray(store.logicalStack) || !store.logicalStack.length) {
      return physical;
    }
    const merged = store.logicalStack.slice();
    const seen = new Set(merged.map(function key(frame) {
      return frame.file + ':' + frame.line + ':' + frame.function;
    }));
    for (const frame of physical) {
      const k = frame.file + ':' + frame.line + ':' + frame.function;
      if (!seen.has(k)) {
        merged.push(frame);
        seen.add(k);
      }
    }
    return merged;
  }

  function reachedTarget(userPath) {
    if (userPath == null || typeof userPath === 'number') {
      return { requested: null, target: null };
    }
    const requested = path.resolve(process.cwd(), String(userPath));
    let real = requested;
    try {
      real = orig.realpathSync(requested);
    } catch (err) {
      real = requested;
    }
    if (real === canaryReal) {
      return { requested: requested, target: 'canary' };
    }
    if (markerReal && real === markerReal) {
      return { requested: requested, target: 'marker' };
    }
    try {
      const st = orig.statSync(requested);
      if (st.dev === canaryId.dev && st.ino === canaryId.ino) {
        return { requested: requested, target: 'canary' };
      }
    } catch (err) {
      // Not present or not the canary.
    }
    return { requested: requested, target: null };
  }

  function recordOpen(userPath, flags, mode) {
    const hit = reachedTarget(userPath);
    if (!hit.target) {
      return;
    }
    const requested = hit.requested && hit.requested.length <= MAX_REQUESTED ? hit.requested : null;
    const record = {
      path: hit.target === 'marker' ? markerReal : canaryReal,
      mode: mode == null ? String(flags) : String(mode),
      op: 'open',
      flags: typeof flags === 'number' ? flags : (fs.constants.O_RDONLY || 0),
      access: accessOf(typeof flags === 'number' ? flags : null, typeof mode === 'string' ? mode : null),
      requested: requested,
      stack: logicalStack(),
      target: hit.target,
      public_interface: isPublicInterface(),
    };
    Object.assign(record, viaSymlink(hit.requested));
    emit(record);
  }

  function innermostAppNames(frames) {
    for (let i = frames.length - 1; i >= 0; i -= 1) {
      if (frames[i].admitted === true) {
        return new Set([frames[i].function, frames[i].qualname]);
      }
    }
    return new Set();
  }

  function recordProcess(api, fileOrCommand, args) {
    const parts = [];
    commandParts(fileOrCommand, parts);
    commandParts(args, parts);
    const frames = logicalStack();
    const sinks = innermostAppNames(frames);
    let named = false;
    for (const name of sinks) {
      if (SINK_NAMES.has(name)) {
        named = true;
        break;
      }
    }
    if (!named) {
      for (const part of parts) {
        if (SINK_NAMES.has(part)) {
          named = true;
          break;
        }
      }
      // The wrapper itself is the sink; an admitted app frame that reached it counts.
      if (!named && frames.some(function admitted(frame) { return frame.admitted === true; })) {
        named = SINK_NAMES.has(api);
      }
    }
    emit({
      path: canaryReal,
      mode: 'child_process.' + api,
      op: 'process',
      flags: null,
      access: 'exec',
      requested: null,
      via_symlink: false,
      stack: frames,
      command: parts.join(' ').slice(0, MAX_COMMAND),
      names_canary: namesCanary(parts, process.cwd(), canaryReal),
      sink_named: named,
      patched: null,
      public_interface: isPublicInterface(),
    });
  }

  function wrapFsMethod(obj, name, original, pathIndex, flagIndex, isSync) {
    const wrapped = function wrappedFs() {
      const args = Array.prototype.slice.call(arguments);
      try {
        recordOpen(args[pathIndex], args[flagIndex], typeof args[flagIndex] === 'string' ? args[flagIndex] : 'r');
      } catch (err) {
        // Observation must never change what the app does.
      }
      return original.apply(this, args);
    };
    freezeProp(obj, name, wrapped);
    return wrapped;
  }

  wrapFsMethod(fs, 'openSync', orig.openSync, 0, 1, true);
  wrapFsMethod(fs, 'open', orig.open, 0, 1, false);
  function wrapRead(obj, name, original) {
    const wrapped = function wrappedRead() {
      const args = Array.prototype.slice.call(arguments);
      try {
        recordOpen(args[0], fs.constants.O_RDONLY, 'r');
      } catch (err) {
        // Observation must never change what the app does.
      }
      return original.apply(this, args);
    };
    freezeProp(obj, name, wrapped);
  }
  wrapRead(fs, 'readFileSync', orig.readFileSync);
  wrapRead(fs, 'readFile', orig.readFile);
  wrapFsMethod(fs, 'writeFileSync', orig.writeFileSync, 0, 1, true);
  wrapFsMethod(fs, 'opendirSync', orig.opendirSync, 0, 1, true);
  wrapFsMethod(fs, 'opendir', orig.opendir, 0, 1, false);
  if (typeof fs.writeFile === 'function') {
    wrapFsMethod(fs, 'writeFile', fs.writeFile.bind(fs), 0, 1, false);
  }
  if (typeof fs.appendFileSync === 'function') {
    wrapFsMethod(fs, 'appendFileSync', fs.appendFileSync.bind(fs), 0, 1, true);
  }

  freezeProp(fs, 'createReadStream', function wrappedCreateReadStream(file, options) {
    try {
      const flags = options && options.flags;
      recordOpen(file, typeof flags === 'number' ? flags : fs.constants.O_RDONLY, flags);
    } catch (err) {
      // ignore
    }
    return orig.createReadStream(file, options);
  });

  freezeProp(fsp, 'readFile', function wrappedPromisesReadFile(file, options) {
    try {
      recordOpen(file, fs.constants.O_RDONLY, 'r');
    } catch (err) {
      // ignore
    }
    return orig.promisesReadFile(file, options);
  });
  freezeProp(fsp, 'open', function wrappedPromisesOpen(file, flags, mode) {
    try {
      recordOpen(file, flags, flags);
    } catch (err) {
      // ignore
    }
    return orig.promisesOpen(file, flags, mode);
  });
  freezeProp(fsp, 'opendir', function wrappedPromisesOpendir(file, options) {
    try {
      recordOpen(file, fs.constants.O_RDONLY, 'r');
    } catch (err) {
      // ignore
    }
    return orig.promisesOpendir(file, options);
  });

  function wrapSpawn(name, original, fileIndex) {
    const wrapped = function wrappedSpawn() {
      const args = Array.prototype.slice.call(arguments);
      try {
        recordProcess(name, args[fileIndex], name === 'exec' || name === 'execSync' ? null : args[fileIndex + 1]);
      } catch (err) {
        // ignore
      }
      return original.apply(this, args);
    };
    freezeProp(childProcess, name, wrapped);
  }
  freezeProp(EventEmitter.prototype, 'emit', function exhibitEmit(type) {
    if (type === 'request' && isHttpServer(this)) {
      const self = this;
      const argv = arguments;
      return als.run({ publicInterface: true, kind: 'http_request' }, function runHttpRequest() {
        return orig.emit.apply(self, argv);
      });
    }
    return orig.emit.apply(this, arguments);
  }, false);

  wrapSpawn('exec', orig.exec, 0);
  wrapSpawn('execSync', orig.execSync, 0);
  wrapSpawn('spawn', orig.spawn, 0);
  wrapSpawn('spawnSync', orig.spawnSync, 0);
  wrapSpawn('execFile', orig.execFile, 0);
  wrapSpawn('execFileSync', orig.execFileSync, 0);
  wrapSpawn('fork', orig.fork, 0);

  freezeProp(process, 'chdir', function wrappedChdir(directory) {
    try {
      emit({
        path: canaryReal, mode: 'process.chdir', op: 'chdir', flags: null, access: 'exec',
        requested: null, via_symlink: false, stack: logicalStack(),
      });
    } catch (err) {
      // ignore
    }
    return orig.chdir(directory);
  });

  const env = process.env;
  const envHandler = {
    set: function setEnv(target, prop, value) {
      const name = String(prop);
      if (SENSITIVE_ENV.has(name) || SENSITIVE_PREFIXES.some(function pref(p) { return name.startsWith(p); })) {
        try {
          emit({
            path: canaryReal, mode: 'process.env', op: 'env', flags: null, access: 'exec',
            requested: null, via_symlink: false, stack: logicalStack(), command: name.slice(0, MAX_FIELD),
          });
        } catch (err) {
          // ignore
        }
      }
      target[prop] = value;
      return true;
    },
    deleteProperty: function delEnv(target, prop) {
      const name = String(prop);
      if (SENSITIVE_ENV.has(name) || SENSITIVE_PREFIXES.some(function pref(p) { return name.startsWith(p); })) {
        try {
          emit({
            path: canaryReal, mode: 'process.env', op: 'env', flags: null, access: 'exec',
            requested: null, via_symlink: false, stack: logicalStack(), command: name.slice(0, MAX_FIELD),
          });
        } catch (err) {
          // ignore
        }
      }
      delete target[prop];
      return true;
    },
  };
  try {
    const proxy = new Proxy(env, envHandler);
    Object.defineProperty(process, 'env', { value: proxy, configurable: false, writable: false });
  } catch (err) {
    // process.env replacement is best-effort on some runtimes.
  }

  function wrapCallable(fn, filename) {
    if (typeof fn !== 'function' || fn.__exhibitAEntry) {
      return fn;
    }
    const wrapped = function wrappedEntry() {
      const args = Array.prototype.slice.call(arguments);
      const selfThis = this;
      const newTarget = new.target;
      const callers = captureFrames();
      const direct = callers.length ? callers[callers.length - 1] : null;
      const fromTest = direct && isTestFile(direct.file);
      function invoke() {
        if (newTarget) {
          return Reflect.construct(fn, args, newTarget);
        }
        return fn.apply(selfThis, args);
      }
      if (fromTest) {
        const self = admit(filename, null);
        self.function = fn.name || self.function || '<anonymous>';
        self.qualname = fn.name || self.qualname || '<anonymous>';
        return als.run({ logicalStack: callers.concat([self]) }, invoke);
      }
      return invoke();
    };
    try {
      Object.defineProperty(wrapped, 'name', { value: fn.name, configurable: true });
      wrapped.prototype = fn.prototype;
      wrapped.__exhibitAEntry = true;
    } catch (err) {
      wrapped.__exhibitAEntry = true;
    }
    return wrapped;
  }

  function wrapPrototype(ctor, filename) {
    if (!ctor || !ctor.prototype || ctor.prototype === Object.prototype) {
      return;
    }
    const names = Object.getOwnPropertyNames(ctor.prototype);
    for (const name of names) {
      if (name === 'constructor') {
        continue;
      }
      const desc = Object.getOwnPropertyDescriptor(ctor.prototype, name);
      if (desc && typeof desc.value === 'function') {
        try {
          ctor.prototype[name] = wrapCallable(desc.value, filename);
        } catch (err) {
          // ignore
        }
      }
    }
  }

  function wrapExports(exported, filename) {
    if (!exported) {
      return exported;
    }
    if (typeof exported === 'function') {
      wrapPrototype(exported, filename);
      return wrapCallable(exported, filename);
    }
    if (typeof exported !== 'object') {
      return exported;
    }
    if (exported.__exhibitAWrapped) {
      return exported;
    }
    for (const key of Object.keys(exported)) {
      try {
        const val = exported[key];
        if (typeof val === 'function') {
          wrapPrototype(val, filename);
          exported[key] = wrapCallable(val, filename);
        }
      } catch (err) {
        // ignore
      }
    }
    try {
      exported.__exhibitAWrapped = true;
    } catch (err) {
      // ignore
    }
    return exported;
  }

  Module._load = function exhibitLoad(request, parent, isMain) {
    const exported = orig.load.apply(this, arguments);
    let filename;
    try {
      filename = Module._resolveFilename(request, parent, isMain);
    } catch (err) {
      return exported;
    }
    try {
      filename = orig.realpathSync(filename);
    } catch (err) {
      filename = path.resolve(filename);
    }
    const rel = relativeToRoot(filename, appRoot);
    if (rel == null || !isDigest(manifestFiles[rel])) {
      return exported;
    }
    return wrapExports(exported, filename);
  };

  Module.createRequire = function exhibitCreateRequire(filename) {
    return orig.createRequire(filename);
  };

  if (orig.binding) {
    process.binding = function exhibitBinding(name) {
      if (name === 'fs' || name === 'spawn_sync') {
        const err = new Error('internal binding trapped');
        err.code = 'EXHIBIT_A_BINDING';
        throw err;
      }
      return orig.binding(name);
    };
    try {
      Object.defineProperty(process, 'binding', { writable: false, configurable: false });
    } catch (err) {
      // ignore
    }
  }
  if (orig.linkedBinding) {
    process._linkedBinding = function exhibitLinked(name) {
      if (name === 'fs' || name === 'spawn_sync') {
        throw new Error('internal binding trapped');
      }
      return orig.linkedBinding(name);
    };
  }

  function injectVm(context) {
    if (!context || typeof context !== 'object') {
      return context;
    }
    try {
      context.fs = fs;
      context.child_process = childProcess;
      context.require = require;
    } catch (err) {
      // ignore
    }
    return context;
  }
  vm.createContext = function exhibitCreateContext(context, options) {
    return orig.vmCreateContext(injectVm(context || Object.create(null)), options);
  };
  vm.runInNewContext = function exhibitRunInNewContext(code, context, options) {
    return orig.vmRunInNewContext(code, injectVm(context || Object.create(null)), options);
  };

  try {
    const worker = require('node:worker_threads');
    const OrigWorker = worker.Worker;
    freezeProp(worker, 'Worker', function ExhibitWorker(entry, options) {
      const opts = Object.assign({}, options || {});
      const execArgv = Array.isArray(opts.execArgv) ? opts.execArgv.slice() : process.execArgv.slice();
      const flag = '--require';
      if (execArgv.indexOf(PLUGIN_FILE) === -1) {
        execArgv.unshift(PLUGIN_FILE);
        execArgv.unshift(flag);
      }
      opts.execArgv = execArgv;
      return new OrigWorker(entry, opts);
    });
  } catch (err) {
    // worker_threads unavailable: nothing to wrap.
  }

  try {
    Object.freeze(fs);
    Object.freeze(fsp);
    Object.freeze(childProcess);
  } catch (err) {
    // freeze is best-effort against casual replacement.
  }

  const protectedIds = new Set();
  try {
    protectedIds.add(require.resolve('node:fs'));
    protectedIds.add(require.resolve('fs'));
    protectedIds.add(require.resolve('node:child_process'));
    protectedIds.add(require.resolve('child_process'));
  } catch (err) {
    // resolve may fail for builtin specifiers on some builds.
  }
  const cacheHandler = {
    deleteProperty: function delCache(target, prop) {
      if (protectedIds.has(prop) || String(prop).indexOf('oracle.cjs') !== -1) {
        return false;
      }
      return delete target[prop];
    },
    set: function setCache(target, prop, value) {
      if (protectedIds.has(prop)) {
        return true;
      }
      target[prop] = value;
      return true;
    },
  };
  try {
    const proxy = new Proxy(require.cache, cacheHandler);
    Object.defineProperty(Module, '_cache', { value: proxy, configurable: false });
  } catch (err) {
    // cache proxy is best-effort.
  }

  const requireFlag = '--require=' + PLUGIN_FILE;
  const existing = process.env.NODE_OPTIONS || '';
  if (existing.indexOf(PLUGIN_FILE) === -1) {
    process.env.NODE_OPTIONS = (existing ? existing + ' ' : '') + requireFlag;
  }

  delete process.env[ENV_EVENTS];
  delete process.env[ENV_CANARY];
  delete process.env[ENV_MARKER];
}

install();
