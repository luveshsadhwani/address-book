import request from "superagent";
import { keyCreate, rootCmd, set } from "../kv.js";
import { withServer } from "./helpers/withServer.js";

describe("HTTP layer", () => {
  it("allows authorized GET/PUT and enforces ACL", async () => {
    await withServer(async (port) => {
      // bootstrap tenant root
      await rootCmd("init", "acme", "alice", "alice");

      // create keys
      const { token: aliceKey } = await keyCreate("acme", "alice", "alice");
      const { token: bobKey } = await keyCreate("acme", "bob", "alice");

      // 3. mark namespace public and write a value (using Alice's key)
      await set("acme:pub", "__acl__", "*", "alice");
      await request
        .put(`http://localhost:${port}/acme/pub/foo`)
        .set("X-Api-Key", aliceKey)
        .send("hello world");

      const res = await request
        .get(`http://localhost:${port}/acme/pub/foo`)
        .set("X-Api-Key", bobKey);

      expect(res.text).toBe("hello world");
      expect(res.status).toBe(200);
    });
  });

  it("rejects unauthorised user (401)", async () => {
    await withServer(async (port) => {
      await rootCmd("init", "globex", "charlie", "charlie");
      await set("globex:secret", "__acl__", "charlie", "charlie");
      await set("globex:secret", "msg", "classified", "charlie");

      // deliberately send a random / invalid key
      const badKey = "deadbeef".repeat(8); // 64-hex chars

      const res = await request
        .get(`http://localhost:${port}/globex/secret/msg`)
        .set("X-Api-Key", badKey)
        .ok(() => true); // don't throw on 4xx

      expect(res.status).toBe(401);
    });
  });

  it("rejects authorised key when ACL forbids (403)", async () => {
    await withServer(async (port) => {
      /* 1 — bootstrap tenant and keys */
      await rootCmd("init", "globex", "charlie", "charlie");
      const { token: malloryKey } = await keyCreate(
        "globex",
        "mallory",
        "charlie"
      );

      /* 2 — namespace ACL lists only charlie */
      await set("globex:secret", "__acl__", "charlie", "charlie");
      await set("globex:secret", "msg", "classified", "charlie");

      /* 3 — Mallory’s key passes verifyApiKey(), then fails authorise() */
      const res = await request
        .get(`http://localhost:${port}/globex/secret/msg`)
        .set("X-Api-Key", malloryKey)
        .ok(() => true); // prevent throw on 4xx

      expect(res.status).toBe(403);
    });
  });

  it("rejects wrong API key", async () => {
    await withServer(async (port) => {
      await rootCmd("init", "acme", "alice", "alice");
      const { token } = await keyCreate("acme", "bob", "alice");
      const bad = "deadbeef" + token.slice(8); // mutate

      const res = await request
        .get(`http://localhost:${port}/acme/foo/bar`)
        .set("X-Api-Key", bad)
        .ok(() => true);

      expect(res.status).toBe(401);
    });
  });
});
