import { set, get, authorize, readLast, rootCmd } from "../kv.js";
import { useIsolatedDataDir } from "./helpers/tmpDir.js";

describe("KV core", () => {
  let cleanup;
  beforeEach(async () => (cleanup = await useIsolatedDataDir()));
  afterEach(() => cleanup());

  it("round-trips a value", async () => {
    await rootCmd("init", "acme", "alice", "alice");
    await set("acme:foo", "k1", "v1", "alice");
    const v = await get("acme:foo", "k1", "alice", true);
    expect(v).toBe("v1");
  });

  it("blocks non-ACL user", async () => {
    await rootCmd("init", "acme", "alice", "alice");
    await set("acme:foo", "__acl__", "alice", "alice");
    await expect(authorize("acme:foo", "bob")).rejects.toThrow();
  });

  it("tenant roots are isolated", async () => {
    await rootCmd("init", "acme", "alice", "alice");
    await rootCmd("init", "globex", "charlie", "charlie");
    await set("globex:bar", "__acl__", "charlie", "charlie");
    await expect(authorize("globex:bar", "alice")).rejects.toThrow();
  });

  it("readLast skips bad JSON", async () => {
    await rootCmd("init", "acme", "alice", "alice");
    await set("acme:foo", "good", "1", "alice");
    const fs = await import("fs/promises");
    await fs.appendFile((await import("../kv.js")).nsPath("acme:foo"), "BAD\n");
    await set("acme:foo", "good", "2", "alice");
    await expect(readLast("acme:foo", "good")).rejects.toThrow(
      /Malformed JSON/
    );
  });

  it('wildcard ACL "*" makes namespace public', async () => {
    // bootstrap tenant and root
    await rootCmd("init", "acme", "alice", "alice");

    // root marks namespace public and writes a value
    await set("acme:public", "__acl__", "*", "alice");
    await set("acme:public", "greeting", "hello", "alice");

    // totally unrelated user can read it
    const val = await readLast("acme:public", "greeting");
    expect(val).toBe("hello");

    // and authorize() does not throw
    await expect(authorize("acme:public", "randomUser")).resolves.not.toThrow();
  });
});
