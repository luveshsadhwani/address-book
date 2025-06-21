import request from "superagent";
import { rootCmd, set } from "../kv.js";
import { withServer } from "./helpers/withServer.js";

describe("HTTP layer", () => {
  it("allows authorized GET/PUT and enforces ACL", async () => {
    await withServer(async (port) => {
      await rootCmd("init", "acme", "alice", "alice");
      await set("acme:pub", "__acl__", "*", "alice");

      await request
        .put(`http://localhost:${port}/acme/pub/foo`)
        .set("X-Principal", "alice")
        .send("hello world");

      const res = await request
        .get(`http://localhost:${port}/acme/pub/foo`)
        .set("X-Principal", "bob");

      expect(res.text).toBe("hello world");
      expect(res.status).toBe(200);
    });
  });

  it("rejects unauthorized user (403)", async () => {
    await withServer(async (port) => {
      await rootCmd("init", "globex", "charlie", "charlie");
      await set("globex:secret", "__acl__", "charlie", "charlie");
      await set("globex:secret", "msg", "classified", "charlie");

      const res = await request
        .get(`http://localhost:${port}/acme/pub/foo`)
        .set("X-Principal", "mallory")
        .ok(() => true); // ignore 403

      expect(res.status).toBe(403);
    });
  });
});
