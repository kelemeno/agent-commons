// A second process for the ledger lock test (test/ledger.test.ts). Not a test
// file itself. Appends `n` admin-signed plantCommit entries to the ledger the
// way LedgerStore and the CLI do: catch up, sign against the head, append, and
// re-sign on "stale".
import * as fs from "node:fs";
import { sha256hex } from "../src/crypto";
import { Ledger, LedgerError, type LedgerState } from "../src/ledger";

const [file, keyFile, tag, n] = process.argv.slice(2) as [string, string, string, string];
const admin = JSON.parse(fs.readFileSync(keyFile, "utf8")) as { publicKey: string; privateKey: string };
const ledger = Ledger.open(file);
let retries = 0;
for (let i = 0; i < Number(n); i++) {
  for (;;) {
    try {
      ledger.refresh();
      ledger.append({ kind: "plantCommit", commitment: sha256hex(`${tag}-${i}`) }, admin, (ledger.state() as LedgerState).headAt);
      break;
    } catch (e) {
      // A forked file reads as stale for ever: give up instead of spinning.
      if (e instanceof LedgerError && e.code === "stale" && ++retries < 20_000) continue;
      console.error(tag, (e as Error).message);
      process.exit(2);
    }
  }
}
