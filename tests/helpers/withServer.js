import { startServer, setDataDir } from "../../kv.js";
import http from "node:http";
import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import * as rimraf from "rimraf";

export async function withServer(testFn) {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), "kv-http-"));
  setDataDir(tmpDir);

  const srv = http.createServer();
  await new Promise((res) => srv.listen(0, res));
  const port = srv.address().port;
  srv.close(); // just getting the port number

  const app = startServer(port);
  try {
    await testFn(port);
  } finally {
    app.close();
    rimraf.sync(tmpDir); // clean up temp directory
  }
}
