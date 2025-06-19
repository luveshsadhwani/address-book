// tests/helpers/tmpDir.js
import { mkdtempSync } from "fs";
import os from "os";
import path from "path";
import * as rimraf from "rimraf";
import * as kv from "../../kv";

export async function useIsolatedDataDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kvtest-"));
  kv.setDataDir(dir);
  return () => rimraf.sync(dir);
}
