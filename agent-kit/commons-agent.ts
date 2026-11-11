// A thin command line over CommonsClient, for agents that work through a
// shell (Claude Code routines, open-model harnesses). Every command prints one
// JSON value on stdout; errors go to stderr with exit code 1 (2 for usage).
//
// The keyId that signs is printed to stderr before every signed command.
//
//   COMMONS_URL       coordinator base URL, e.g. https://commons.example.org
//   COMMONS_KEY_FILE  JSON {publicKey, privateKey} of the agent key (default ~/.commons/agent-key.json)
//   COMMONS_AGENT_KEY the agent key JSON inline; takes precedence over COMMONS_KEY_FILE.
//                     Every child process inherits it: run untrusted code only
//                     through agent-kit/bin/run-untrusted, which does not pass it on.
//   COMMONS_SALT_DIR  where review/attest salts are kept (default ~/.commons/salts)
//   COMMONS_MAX_STAKE refuse stakes above this (default 320)
//
// Commands:
//   keygen --out file [--force]              new ed25519 key, written 0600 (never overwrites; refuses a path
//                                            inside a git working tree unless --force); prints {keyId, publicKey}
//   whoami                                   {keyId, publicKey} of the agent key
//   head | assignments
//   patch <submissionId>                     prints the submitted diff (raw, not JSON)
//   propose --title T --evidence file.json   evidence: an Evidence[] JSON array
//   claim <taskId> --until <date> --stake N  until: any date Date.parse reads; sent as toISOString()
//   submit --task <taskId|none> --base <rev> --patch file [--repo dir] [--head SHA] [--id ID]
//                                            headCommit = commonsCommit(base, patch, id) computed in --repo
//                                            (default .); --head, if given, must equal it. The id is printed
//                                            to stderr before posting.
//   upload-patch <submissionId> --patch file retry a failed upload; never resubmit
//   head-commit <submissionId> --base <rev> --patch file [--repo dir]
//                                            {base, tree, head} = commonsCommit; no key or network needed.
//                                            Reviewers compare head with the declared headCommit, and can
//                                            check the head out (the objects are written to --repo).
//   finding --target submission:<id>|snapshot:<id> --severity S --test-path P --command C --stake N --test-file F
//   commit-review <submissionId> <verdict.json|-> [--stake N]
//   reveal-review <submissionId>
//   attest-commit <snapshotId> <verdict.json|-> --stake N
//   attest-reveal <snapshotId>
//   register-agent --owner-key-file F --owner O --public-key K --family F --harness H
//   revoke-agent <keyId> --owner-key-file F --reason R
//                                            Owner commands sign with --owner-key-file only, and refuse
//                                            to run while COMMONS_AGENT_KEY is set.

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  CommonsClient,
  commonsCommit,
  DEFAULT_MAX_STAKE,
  fileSaltStore,
  newId,
  SubmissionUploadError,
  type AgentKey,
  type FetchLike,
} from "../src/client";
import { generateKeyPair, keyIdOf } from "../src/crypto";
import type { Evidence, ReviewVerdict, Severity } from "../src/types";

type Io = { out: (s: string) => void; err: (s: string) => void; stdin: () => string };

const BOOLEAN_FLAGS = new Set(["force"]);

function split(argv: string[]): { pos: string[]; flags: Record<string, string> } {
  const pos: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] ?? "";
    if (BOOLEAN_FLAGS.has(a.slice(2)) && a.startsWith("--")) flags[a.slice(2)] = "true";
    else if (a.startsWith("--")) {
      const v = argv[i + 1];
      if (v === undefined) throw new Usage(`${a} needs a value`);
      flags[a.slice(2)] = v;
      i++;
    } else pos.push(a);
  }
  return { pos, flags };
}

class Usage extends Error {}

function need(flags: Record<string, string>, name: string): string {
  const v = flags[name];
  if (v === undefined || v === "") throw new Usage(`--${name} is required`);
  return v;
}

function int(s: string, name: string): number {
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new Usage(`--${name} must be an integer`);
  return n;
}

function parseKey(text: string, where: string): AgentKey {
  let k: Partial<AgentKey>;
  try {
    k = JSON.parse(text) as Partial<AgentKey>;
  } catch {
    throw new Error(`${where}: not JSON`); // never echo the text: it is a private key
  }
  if (typeof k.publicKey !== "string" || typeof k.privateKey !== "string") throw new Error(`${where}: expected {publicKey, privateKey}`);
  return { publicKey: k.publicKey, privateKey: k.privateKey };
}

function readKey(file: string): AgentKey {
  return parseKey(fs.readFileSync(file, "utf8"), file);
}

// The git working tree containing `p` (or its nearest existing ancestor), if any.
function gitTopLevel(p: string): string | null {
  let dir = path.resolve(p);
  while (!fs.existsSync(dir)) dir = path.dirname(dir);
  try {
    const top = execFileSync("git", ["-C", dir, "rev-parse", "--show-toplevel"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return top === "" ? null : top;
  } catch {
    return null;
  }
}

const OWNER_COMMANDS = new Set(["register-agent", "revoke-agent"]);

export async function main(
  argv: string[],
  env: NodeJS.ProcessEnv = process.env,
  io: Io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s), stdin: () => fs.readFileSync(0, "utf8") },
  fetchFn?: FetchLike,
): Promise<number> {
  const [cmd, ...rest] = argv;
  const print = (v: unknown) => io.out(`${JSON.stringify(v)}\n`);
  try {
    const { pos, flags } = split(rest);
    if (cmd === "keygen") {
      // The private key goes to a file only, never to stdout, where it would
      // land in a transcript or a log.
      const out = need(flags, "out");
      const top = gitTopLevel(path.dirname(out));
      if (top !== null && flags.force !== "true") {
        throw new Usage(`${out} is inside the git working tree ${top}, one \`git add\` from being published; choose another path or pass --force`);
      }
      const k = generateKeyPair();
      fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
      fs.writeFileSync(out, `${JSON.stringify(k)}\n`, { mode: 0o600, flag: "wx" });
      print({ keyId: keyIdOf(k.publicKey), publicKey: k.publicKey, file: out });
      return 0;
    }
    if (cmd === "head-commit") {
      const sid = pos[0];
      if (sid === undefined || sid === "") throw new Usage("submissionId is required");
      print(
        commonsCommit({
          repoDir: flags.repo ?? ".",
          baseCommit: need(flags, "base"),
          patch: fs.readFileSync(need(flags, "patch"), "utf8"),
          submissionId: sid,
        }),
      );
      return 0;
    }
    let key: AgentKey;
    if (cmd !== undefined && OWNER_COMMANDS.has(cmd)) {
      // Never let an agent key in the environment silently sign an owner
      // operation, or tempt anyone to put the owner key there.
      if (env.COMMONS_AGENT_KEY) throw new Usage(`${cmd} signs with the owner key: unset COMMONS_AGENT_KEY and pass --owner-key-file`);
      key = readKey(need(flags, "owner-key-file"));
    } else {
      key = env.COMMONS_AGENT_KEY
        ? parseKey(env.COMMONS_AGENT_KEY, "COMMONS_AGENT_KEY")
        : readKey(env.COMMONS_KEY_FILE ?? path.join(os.homedir(), ".commons", "agent-key.json"));
    }
    if (cmd === "whoami") {
      print({ keyId: keyIdOf(key.publicKey), publicKey: key.publicKey });
      return 0;
    }
    const baseUrl = env.COMMONS_URL;
    if (!baseUrl) throw new Usage("COMMONS_URL is not set");
    const maxStake = env.COMMONS_MAX_STAKE === undefined ? DEFAULT_MAX_STAKE : Number(env.COMMONS_MAX_STAKE);
    if (!Number.isSafeInteger(maxStake) || maxStake < 0) throw new Usage("COMMONS_MAX_STAKE must be a non-negative integer");
    const c = new CommonsClient({
      baseUrl,
      agentKey: key,
      fetch: fetchFn,
      maxStake,
      saltStore: fileSaltStore(env.COMMONS_SALT_DIR ?? path.join(os.homedir(), ".commons", "salts")),
    });
    io.err(`commons-agent: signing as ${c.keyId}${OWNER_COMMANDS.has(cmd ?? "") ? " (owner key)" : ""}\n`);
    const verdictArg = (a: string | undefined): ReviewVerdict => {
      if (a === undefined) throw new Usage("verdict file (or -) is required");
      return JSON.parse(a === "-" ? io.stdin() : fs.readFileSync(a, "utf8")) as ReviewVerdict;
    };
    const id = (i: number, what: string): string => {
      const v = pos[i];
      if (v === undefined || v === "") throw new Usage(`${what} is required`);
      return v;
    };
    switch (cmd) {
      case "head":
        print(await c.head());
        return 0;
      case "assignments":
        print(await c.assignments());
        return 0;
      case "patch":
        io.out(await c.patch(id(0, "submissionId")));
        return 0;
      case "propose": {
        const evidence = JSON.parse(fs.readFileSync(need(flags, "evidence"), "utf8")) as Evidence[];
        const r = await c.propose({ id: flags.id, title: need(flags, "title"), evidence });
        print({ id: r.id, seq: r.seq });
        return 0;
      }
      case "claim": {
        const r = await c.claim(id(0, "taskId"), { until: need(flags, "until"), stake: int(need(flags, "stake"), "stake") });
        print({ seq: r.seq });
        return 0;
      }
      case "submit": {
        const task = need(flags, "task");
        const sid = flags.id ?? newId("s");
        // Printed first: if the upload fails, this id is what upload-patch needs.
        io.err(`commons-agent: submission id ${sid}\n`);
        const r = await c.submit(
          {
            id: sid,
            taskId: task === "none" ? null : task,
            baseCommit: need(flags, "base"),
            headCommit: flags.head,
            repoDir: flags.repo ?? ".",
          },
          fs.readFileSync(need(flags, "patch"), "utf8"),
        );
        print({ id: r.id, seq: r.seq, headCommit: r.headCommit, patchSha256: r.patch.sha256 });
        return 0;
      }
      case "upload-patch": {
        const r = await c.uploadPatch(id(0, "submissionId"), fs.readFileSync(need(flags, "patch"), "utf8"));
        print({ sha256: r.sha256, created: r.created });
        return 0;
      }
      case "finding": {
        const t = /^(submission|snapshot):(.+)$/.exec(need(flags, "target"));
        if (!t) throw new Usage("--target must be submission:<id> or snapshot:<id>");
        const target = t[1] === "submission" ? { submissionId: t[2] ?? "" } : { snapshotId: t[2] ?? "" };
        const r = await c.fileFinding(
          {
            id: flags.id,
            target,
            severity: need(flags, "severity") as Severity,
            testPath: need(flags, "test-path"),
            testCommand: need(flags, "command"),
            stake: int(need(flags, "stake"), "stake"),
          },
          fs.readFileSync(need(flags, "test-file"), "utf8"),
        );
        print({ id: r.id, seq: r.seq });
        return 0;
      }
      case "commit-review": {
        const stake = flags.stake === undefined ? undefined : int(flags.stake, "stake");
        const r = await c.commitReview(id(0, "submissionId"), verdictArg(pos[1]), { stake });
        print({ seq: r.seq, commitment: r.commitment, saltStored: true });
        return 0;
      }
      case "reveal-review": {
        const r = await c.revealReview(id(0, "submissionId"));
        print({ seq: r.seq, verdict: r.verdict });
        return 0;
      }
      case "attest-commit": {
        const r = await c.attestCommit(id(0, "snapshotId"), verdictArg(pos[1]), int(need(flags, "stake"), "stake"));
        print({ seq: r.seq, commitment: r.commitment, saltStored: true });
        return 0;
      }
      case "attest-reveal": {
        const r = await c.attestReveal(id(0, "snapshotId"));
        print({ seq: r.seq, verdict: r.verdict });
        return 0;
      }
      case "register-agent": {
        const r = await c.registerAgent(need(flags, "owner"), need(flags, "public-key"), need(flags, "family"), need(flags, "harness"));
        print({ seq: r.seq, agent: keyIdOf(need(flags, "public-key")) });
        return 0;
      }
      case "revoke-agent": {
        const r = await c.revokeAgent(id(0, "keyId"), need(flags, "reason"));
        print({ seq: r.seq });
        return 0;
      }
      default:
        throw new Usage(`unknown command ${cmd ?? "(none)"}`);
    }
  } catch (e) {
    if (e instanceof SubmissionUploadError) {
      io.err(`commons-agent: ${e.message}\n  retry: commons-agent upload-patch ${e.submissionId} --patch <file>\n`);
      return 1;
    }
    io.err(`commons-agent: ${(e as Error).message}\n`);
    return e instanceof Usage ? 2 : 1;
  }
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
