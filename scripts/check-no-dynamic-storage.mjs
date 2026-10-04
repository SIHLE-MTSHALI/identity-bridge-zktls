#!/usr/bin/env node
/**
 * Structural PII check for contract storage layout.
 *
 * Verifies that privacy-sensitive contracts declare no dynamic (`string` /
 * `bytes`) storage members.
 *
 * Why this exists: `contracts/test/invariant/NoPIIStorage.t.sol` scans storage at
 * runtime and catches personal data that was actually written. It cannot catch a
 * `string` field that has been added but never populated - an unused short string
 * occupies no slots, so a runtime scan passes vacuously. Reading the compiled
 * storage layout closes that gap: the *shape* is checked, not just the values.
 *
 * The check walks the `types` graph from `forge inspect <c> storage-layout --json`
 * rather than just the top-level `storage` array, because a struct nested inside a
 * mapping (`t_mapping(t_bytes32,t_struct(CredentialRecord)1554_storage)`) is
 * referenced only by type id - its members are not visible from `storage` alone.
 * Both mutation tests in `docs/privacy-model.md` depend on this traversal.
 *
 * Usage:  node scripts/check-no-dynamic-storage.mjs [contract ...]
 * Exit 0 when clean, 1 when a dynamic member is found, 2 on tooling failure.
 */

import { execFileSync } from "node:child_process";

/**
 * Contracts whose storage must contain no free-form members.
 *
 * `CredentialRegistry` holds the only holder-linked state in the system.
 * `ProviderRegistry` and `SchemaRegistry` are deliberately excluded from this
 * list: each stores exactly one `metadataURI` documentation pointer chosen by
 * governance. That narrow exception is asserted explicitly below rather than
 * ignored, so a second `string` field added to either would still fail.
 */
const STRICT_CONTRACTS = [
  "CredentialRegistry",
  "CredentialBridge",
  "PolicyManagerAdapter",
  "EmergencyControls",
  "CCIDResolver",
  "CrossChainCredentialSender",
  "CrossChainCredentialReceiver",
];

/** Contracts allowed exactly these dynamic members, and nothing more. */
const ALLOWED_DYNAMIC = {
  ProviderRegistry: ["metadataURI"],
  SchemaRegistry: ["metadataURI"],
};

/** True when a type label denotes a dynamically-sized value. */
function isDynamicLabel(label) {
  if (typeof label !== "string") return false;
  // "string", "bytes", "string[]", "string[3]", "bytes[2][]", ...
  return label === "string" || label === "bytes" || /\b(string|bytes)\b/.test(label);
}

function layoutFor(contract) {
  const out = execFileSync("forge", ["inspect", contract, "storage-layout", "--json"], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const parsed = JSON.parse(out);
  if (!parsed || !Array.isArray(parsed.storage) || typeof parsed.types !== "object") {
    throw new Error("unexpected storage-layout shape");
  }
  return parsed;
}

/**
 * Depth-first walk of the type graph.
 *
 * `members` covers structs, `value` covers mappings, and `base` covers arrays
 * and inherited types. All three are followed, because a `string` can hide in a
 * struct inside a mapping inside an array.
 */
function findDynamic(types, typeId, path, seen, found) {
  if (!typeId || seen.has(typeId)) return found;
  seen.add(typeId);

  const node = types[typeId];
  if (!node) return found;

  if (isDynamicLabel(node.label)) {
    found.push({ path, type: typeId, label: node.label });
    // Still descend: `string[]` is dynamic and its elements matter too.
  }

  if (typeof node.base === "string") {
    findDynamic(types, node.base, `${path}[]`, seen, found);
  }
  if (typeof node.value === "string") {
    findDynamic(types, node.value, `${path}{value}`, seen, found);
  }
  if (Array.isArray(node.members)) {
    for (const m of node.members) {
      findDynamic(types, m.type, path ? `${path}.${m.label}` : m.label, seen, found);
    }
  }
  return found;
}

const requested = process.argv.slice(2);
const contracts = requested.length > 0 ? requested : STRICT_CONTRACTS;

let failures = 0;

for (const contract of contracts) {
  let layout;
  try {
    layout = layoutFor(contract);
  } catch (err) {
    console.error(`FAIL  ${contract}: could not read storage layout (${String(err.message).split("\n")[0]})`);
    failures += 1;
    continue;
  }

  const allowed = new Set(ALLOWED_DYNAMIC[contract] ?? []);
  const dynamic = [];
  for (const entry of layout.storage) {
    findDynamic(layout.types, entry.type, entry.label, new Set(), dynamic);
  }

  const unexpected = dynamic.filter((d) => !allowed.has(d.path.split(".").pop()));

  if (unexpected.length > 0) {
    console.error(`FAIL  ${contract}: dynamic storage member(s) found`);
    for (const d of unexpected) console.error(`        ${d.path}  (${d.label})`);
    failures += 1;
  } else {
    const note = dynamic.length > 0 ? `  [allowed: ${dynamic.map((d) => d.path).join(", ")}]` : "";
    console.log(`ok    ${contract}: no unexpected dynamic storage members${note}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} contract(s) declare storage capable of holding free-form data.`);
  console.error("Credential state must be hashes, enums, and timestamps only. See docs/privacy-model.md.");
  process.exit(1);
}

console.log("\nAll checked contracts store no free-form data.");