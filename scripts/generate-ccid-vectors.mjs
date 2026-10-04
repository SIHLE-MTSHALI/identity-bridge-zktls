#!/usr/bin/env node
/**
 * Regenerate CCID parity vectors from the on-chain resolver.
 *
 * Runs `forge script contracts/script/GenerateCcidVectors.s.sol`, extracts the
 * emitted JSON objects, and writes them to `workflows/test/vectors/ccid-vectors.json`.
 *
 * The vectors must come from the contract rather than being written by hand: a
 * hand-copied vector only proves the TypeScript matches what someone typed, not
 * that it matches the code that will validate it. Regenerating is cheap, so CI
 * checks that the committed file is up to date.
 *
 * Usage: node scripts/generate-ccid-vectors.mjs
 */

import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..");
const outPath = resolve(repoRoot, "workflows/test/vectors/ccid-vectors.json");

const raw = execFileSync("forge", ["script", "contracts/script/GenerateCcidVectors.s.sol"], {
  cwd: repoRoot,
  encoding: "utf8",
  maxBuffer: 32 * 1024 * 1024,
});

/**
 * `forge script` prefixes console output with log metadata and ANSI colour codes,
 * so each line is stripped before the JSON objects are recovered.
 */
function stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\u001b\[[0-9;]*m/g, "");
}

const lines = stripAnsi(raw)
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => l.startsWith("{") && (l.includes('"domain"') || l.includes('"ccid"')));

const header = lines.find((l) => l.includes('"domain"'));
if (header === undefined) {
  console.error("Could not find the domain header in forge output.");
  console.error(stripAnsi(raw).slice(0, 2000));
  process.exit(2);
}

/** The header is a deliberately unterminated JSON fragment, so extract with a regex. */
const domainMatch = /"domain"\s*:\s*"(0x[0-9a-fA-F]{64})"/.exec(header);
if (domainMatch === null) {
  console.error(`Could not parse the domain out of: ${header}`);
  process.exit(2);
}
const domain = domainMatch[1];

const vectors = lines
  .filter((l) => l.includes('"ccid"'))
  .map((l) => JSON.parse(l.replace(/,\s*$/, "")));

if (vectors.length === 0) {
  console.error("No CCID vectors found in forge output.");
  process.exit(2);
}

const payload = { domain, vectors };

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");

console.log(`wrote ${vectors.length} CCID vectors to ${outPath}`);
console.log(`domain: ${domain}`);