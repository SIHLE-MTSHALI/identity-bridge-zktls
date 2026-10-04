#!/usr/bin/env node
/**
 * Contract size gate.
 *
 * Fails when any contract's runtime bytecode exceeds the EIP-170 deployment
 * limit, or when no artifacts are found at all — an empty result from a broken
 * glob would otherwise read as "everything is fine".
 *
 * Written in Node rather than a `jq | find | awk` pipeline because every one of
 * those utilities differs between a Windows shell and a Linux CI runner, and a
 * check that only works on one platform is not a check.
 *
 * Usage: node scripts/check-contract-sizes.mjs [artifactDir]
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

/** EIP-170. Above this, deployment reverts. */
const LIMIT = 24_576;

/** Default artifact directory, matching `foundry.toml`'s `out`. */
const artifactDir = process.argv[2] ?? "out";

function collectJson(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...collectJson(p));
    else if (entry.name.endsWith(".json")) out.push(p);
  }
  return out;
}

/**
 * Skip test and script artifacts.
 *
 * EIP-170 applies to contracts that get *deployed*; test contracts and Foundry
 * scripts never are, and they are legitimately far larger because they embed
 * cheatcode helpers or an entire system. Including them made this check fail on a
 * repository whose deployable contracts are all well within the limit.
 *
 * Matched on the `.t.sol` / `.s.sol` artifact directory, because Foundry names the
 * artifact directory after the source file, not the source directory:
 * `contracts/script/Deploy.s.sol` builds to `out/Deploy.s.sol/Deploy.json`.
 */
function isDeployableArtifact(file) {
  const normalised = file.split("\\").join("/");
  return !/\/[^/]*\.t\.sol\//.test(normalised) && !/\/[^/]*\.s\.sol\//.test(normalised);
}

const files = collectJson(artifactDir).filter(isDeployableArtifact);

if (files.length === 0) {
  console.error(`::error::no JSON artifacts found under ${artifactDir}/ - did \`forge build\` run?`);
  process.exit(1);
}

const sizes = [];

for (const file of files) {
  let json;
  try {
    json = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    // Build-info and other non-contract JSON; not an error.
    continue;
  }
  const code = json?.deployedBytecode?.object;
  if (typeof code !== "string") continue;

  // Prefer the artifact's own metadata for a readable name; `statSync` is only a
  // last resort because several artifacts can share a filename across directories.
  let name = json.metadata?.settings?.compilationTarget
    ?? json.metadata?.settings?.fullyQualifiedName
    ?? json.contractName
    ?? file;
  if (typeof name !== "string") name = file;

  // Forge emits the raw bytecode as a hex string, but `bytecode.object` may also
  // arrive as a `{ object }` wrapper depending on version. Only count it when it
  // really is hex, and otherwise report the file so a surprise shows up in the log.
  const hex = /^0x[0-9a-fA-F]*$|^[0-9a-fA-F]*$/.test(code);
  if (!hex) {
    console.warn(`skipping ${name}: runtime bytecode is not a hex string (unexpected format)`);
    continue;
  }
  if (code.length === 0) continue;

  // Hex string: two characters per byte.
  sizes.push({ name, size: Math.floor(code.length / 2) });
}

if (sizes.length === 0) {
  console.error(`::error::found ${files.length} JSON files under ${artifactDir}/ but none carried runtime bytecode.`);
  console.error("This usually means the build did not run or produced only build-info.");
  process.exit(1);
}

sizes.sort((a, b) => b.size - a.size);

const largest = sizes[0];
console.log(`${sizes.length} contracts, largest ${largest.size} B (${largest.name}), limit ${LIMIT} B`);

// Report the top few so a regression is visible in the log, not just as a failure.
for (const s of sizes.slice(0, 5)) {
  const margin = LIMIT - s.size;
  console.log(`  ${String(s.size).padStart(6)} B  ${s.name}  (${margin} B margin)`);
}

const oversized = sizes.filter((s) => s.size > LIMIT);
if (oversized.length > 0) {
  console.error(`::error::${oversized.length} contract(s) exceed the EIP-170 limit:`);
  for (const s of oversized) console.error(`  ${s.name}: ${s.size} B > ${LIMIT} B`);
  process.exit(1);
}

console.log("all contracts are within the deployment limit");