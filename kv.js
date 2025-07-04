import fs from "fs";
import { promises as fsp } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import readline from "readline";
import crypto from "node:crypto";
/* ---------- HTTP wrapper (built-ins only) ---------- */
import http from "http";
import { URL } from "url";

function startServer(port = 8080) {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      // Admin endpoints start with /admin/
      if (url.pathname.startsWith(`/admin/`)) {
        const [, , tenant, ...rest] = url.pathname.split("/");
        const token = req.headers["x-api-key"];
        const principal = await verifyApiKey(tenant, token);
        if (!(await isRoot(principal, tenant))) {
          res.writeHead(403).end("Not tenant root");
          return;
        }

        // POST /admin/<tenant>/keys
        if (req.method === "POST" && rest[0] === "keys" && rest.length === 1) {
          const { owner } = JSON.parse(await readBody(req));
          const { token, tokenId } = await keyCreate(tenant, owner, principal);
          res
            .writeHead(201, { "Content-Type": "application/json" })
            .end(JSON.stringify({ token, tokenId }));
          return;
        }

        // DELETE /admin/<tenant>/keys/<tokenId>
        if (
          req.method === "DELETE" &&
          rest[0] === "keys" &&
          rest.length === 2
        ) {
          await revokeKey(tenant, rest[1], principal);
          res.writeHead(204).end();
          return;
        }

        // POST /admin/<tenant>/rotate-root
        if (req.method === "POST" && rest[0] === "rotate-root") {
          const { newRoot } = JSON.parse(await readBody(req));
          await rootCmd("rotate", tenant, newRoot, principal);
          res.writeHead(204).end();
          return;
        }

        res.writeHead(404).end("Unknown admin route");
        return;
      }

      // Endpoint       /<tenant>/<namespace>/<key>
      const [, tenant, namespace, ...keyParts] = url.pathname.split("/");
      const key = keyParts.join("/"); // support slashes in key
      const token = req.headers["x-api-key"];
      const principal = await verifyApiKey(tenant, token);
      if (!principal) {
        res.writeHead(401).end("Invalid API key");
        return;
      }

      if (!tenant || !namespace || !key || !principal) {
        res.writeHead(400).end("Bad request");
        return;
      }
      const ns = `${tenant}:${namespace}`;

      if (req.method === "GET") {
        await authorize(ns, principal); // ACL / root check
        const value = await readLast(ns, key);
        if (value === null) {
          res.writeHead(404).end("Not found");
          return;
        }
        res.writeHead(200, { "Content-Type": "text/plain" }).end(value);
        return;
      }

      if (req.method === "PUT") {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const body = Buffer.concat(chunks).toString("utf8");
        await set(ns, key, body, principal);
        res.writeHead(204).end();
        return;
      }

      res.writeHead(405).end("Method not allowed");
    } catch (err) {
      console.error("Error handling request:", err);
      res.writeHead(403).end(err.message);
    }
  });

  server.listen(port, () =>
    console.log(`KV HTTP server listening on http://localhost:${port}`)
  );
  return server; // return server instance for testing
}

async function verifyApiKey(tenant, token) {
  const tokenId = token.slice(0, 8);
  const rec = await readLast(`${tenant}:__keys__`, tokenId);
  if (!rec) return null;
  const { hash, owner, active } = rec;
  if (!active) return null; // token is inactive

  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(tokenHash))) {
    return null;
  }
  return owner;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export let DATA_DIR = path.join(__dirname, "data");
export function setDataDir(dir) {
  DATA_DIR = dir; // helper to set DATA_DIR in testing
}

const ACL_KEY = "__acl__";
const META_NS = "__meta__";
const ROOT_PREF = "__root__:";

function getTenant(ns) {
  return ns.split(":")[0]; // "acme:customers" -> "acme"
}

const readRoot = (tenant) => readLast(META_NS, ROOT_PREF + tenant);

const isRoot = async (principal, tenant) => {
  const root = await readRoot(tenant);
  return root !== null && root === principal;
};

function nsPath(ns) {
  if (ns === META_NS) return path.join(DATA_DIR, `${META_NS}.jsonl`);

  const [tenant, name] = ns.split(":");
  if (!tenant || !name)
    throw new Error('Namespace must be in "<tenant>:<name>" form');

  return path.join(DATA_DIR, tenant, `${name}.jsonl`);
}

async function authorize(ns, principal) {
  const tenant = getTenant(ns);
  if (await isRoot(principal, tenant)) return;

  const acl = await readLast(ns, ACL_KEY); // "alice,bob" | "*" | null
  if (!acl) throw new Error("ACL missing; bootstrap first");
  if (acl !== "*" && !acl.split(",").includes(principal))
    throw new Error("Forbidden");
}

async function rootCmd(action, tenant, newName, principal) {
  const current = await readRoot(tenant);

  if (action === "init") {
    if (current) throw new Error(`Root already set to "${current}"`);
  } else if (!(await isRoot(principal, tenant))) {
    throw new Error("Only current root may rotate");
  }

  await appendRecord(META_NS, { k: ROOT_PREF + tenant, v: newName });
  console.log(
    action === "init"
      ? `Root for ${tenant} is now "${newName}"`
      : `Root for ${tenant} rotated to "${newName}"`
  );
}

/**
 * Stream-scan <namespace>.jsonl and return the *last* value written
 * for `wantedKey`.  If the key never appears, resolve to null.
 */
async function readLast(ns, wantedKey) {
  const file = nsPath(ns);
  try {
    // namespace might not exist yet
    await fsp.access(file);
  } catch {
    return null;
  }

  let last = null;
  const rl = readline.createInterface({
    input: fs.createReadStream(file, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      throw new Error(`Malformed JSON in ${nsPath(ns)}: "${line}"`);
    }
    if (rec.k === wantedKey) last = rec.v; // overwrite until the end
  }
  return last; // null ⟺ never seen
}

async function set(ns, key, value, principal) {
  await authorize(ns, principal);
  await appendRecord(ns, { k: key, v: value });
  console.log("OK");
}

async function get(ns, key, principal) {
  await authorize(ns, principal);
  const file = nsPath(ns);
  try {
    await fsp.access(file);
  } catch {
    console.error("Namespace not found");
    process.exit(1);
  }

  const val = await readLast(ns, key);
  if (val === null) process.exit(1);
  return val;
}

/**
 * createKey(tenant, owner) -> { token, tokenId }
 * Appends a key record to <tenant>:__keys__
 */
async function keyCreate(tenant, owner, principal) {
  if (!(await isRoot(principal, tenant)))
    throw new Error("Only tenant root may create keys");

  const raw = crypto.randomBytes(32).toString("hex"); // 64-char token
  const tokenId = raw.slice(0, 8); // first 8 chars = id
  const hash = crypto.createHash("sha256").update(raw).digest("hex");

  await appendRecord(`${tenant}:__keys__`, {
    k: tokenId,
    v: { hash, owner, active: true },
  });
  console.log(`New key for ${owner} → ${raw}`); // show once
  return { token: raw, tokenId };
}

/**
 * revokeKey(tenant, tokenId, principal)
 * Only tenant root may revoke; marks key inactive.
 */
async function revokeKey(tenant, tokenId, principal) {
  if (!(await isRoot(principal, tenant)))
    throw new Error("Only tenant root may revoke keys");

  const rec = await readLast(`${tenant}:__keys__`, tokenId);
  if (!rec) throw new Error("Key not found");

  const { hash, owner } = rec;
  await appendRecord(`${tenant}:__keys__`, {
    k: tokenId,
    v: { hash, owner, active: false },
  });
  console.log(`Key ${tokenId} revoked`);
}

async function main() {
  const args = process.argv.slice(2);

  const asIdx = args.indexOf("--as");
  if (asIdx === -1 || asIdx === args.length - 1) {
    console.error("Usage: kv --as <user> <get|set> <namespace> <key> [value]");
    process.exit(1);
  }
  const principal = args[asIdx + 1];
  args.splice(asIdx, 2);

  const withKeyIdx = args.indexOf("--with-key");
  const withKey = withKeyIdx !== -1;
  if (withKey) args.splice(withKeyIdx, 1);

  const [cmd, ns, key, ...rest] = args;
  if (!cmd || !ns || !key || (cmd === "set" && rest.length === 0)) {
    console.error("Usage: kv --as <user> <get|set> <namespace> <key> [value]");
    process.exit(1);
  }

  if (cmd === "root") {
    const [action, tenant, newName] = [ns, key, rest[0]];
    await rootCmd(action, tenant, newName, principal);
    if (action === "init" && withKey) {
      // the freshly created root is `newName`
      await keyCreate(tenant, newName, newName);
    }
  } else if (cmd === "set") {
    await set(ns, key, rest.join(" "), principal);
  } else if (cmd === "get") {
    await get(ns, key, principal);
  } else if (cmd === "key") {
    const [action, tenant, arg] = [ns, key, rest[0]]; // ns holds action
    if (action === "create") {
      await keyCreate(tenant, arg, principal); // arg = owner
    } else if (action === "revoke") {
      await revokeKey(tenant, arg, principal); // arg = tokenId
    } else {
      console.error("Usage: key <create|revoke> …");
      process.exit(1);
    }
  } else {
    console.error("Unknown command");
    process.exit(1);
  }
}

async function appendRecord(ns, obj) {
  const file = nsPath(ns);
  await fsp.mkdir(path.dirname(file), { recursive: true });
  let prefix = "";

  try {
    const h = await fsp.open(file, "r");
    const { size } = await h.stat();
    if (size > 0) {
      // read the last byte to see if it is '\n'
      const buf = Buffer.alloc(1);
      await h.read(buf, 0, 1, size - 1);
      if (buf[0] !== 0x0a) prefix = "\n"; // add newline if missing
    }
    await h.close();
  } catch {
    /* file does not exist yet → no prefix needed */
  }

  const line = prefix + JSON.stringify(obj) + "\n";
  await fsp.appendFile(file, line, "utf8");
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

if (process.argv[2] === "serve") {
  const port = Number(process.argv[3]) || 8080;
  startServer(port);
  //  keep node alive – no call to main()
} else if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

export {
  set,
  get,
  authorize,
  readLast,
  rootCmd,
  nsPath,
  startServer,
  keyCreate,
};
