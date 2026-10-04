import type { Address, Hex, PublicClient, WalletClient } from "viem";
import { providerStatusName, type ProviderStatusName } from "./types.js";
import { toProvider, type ProviderInfo } from "./decode.js";

/**
 * @file providerClient
 *
 * Provider registry reads, plus the two status distinctions integrators most often
 * get wrong.
 */

export interface ProviderRegistryLike {
  address: Address;
  abi: readonly unknown[];
}

/** A provider's registry entry. */
export interface ProviderStatusResult {
  providerId: Hex;
  registered: boolean;
  status: number;
  statusName: ProviderStatusName;
  metadataURI: string;
  lastHeartbeat: bigint;
  failureCount: bigint;
  /** True while the provider is `Active`, registered, and not failing. */
  healthy: boolean;
}

/** Read a provider's full registry entry plus derived health. */
export async function getProviderStatus(
  client: PublicClient,
  providers: ProviderRegistryLike,
  providerId: Hex,
): Promise<ProviderStatusResult> {
  const [raw, healthy] = await Promise.all([
    client.readContract({ address: providers.address, abi: providers.abi, functionName: "getProvider", args: [providerId] }),
    client.readContract({ address: providers.address, abi: providers.abi, functionName: "isProviderHealthy", args: [providerId] }),
  ]);

  const info = toProvider(raw as readonly unknown[]);
  return {
    providerId,
    registered: info.registered,
    status: info.status,
    statusName: providerStatusName(info.status),
    metadataURI: info.metadataURI,
    lastHeartbeat: info.lastHeartbeat,
    failureCount: info.failureCount,
    healthy: Boolean(healthy),
  };
}

/**
 * Does this provider still back credentials that already exist?
 *
 * The distinction that matters in practice:
 *
 * - `Deprecated` returns **true**. A planned wind-down must not retroactively
 *   invalidate credentials integrators already reasoned about.
 * - `Paused` and `Revoked` return **false**, and every policy decision denies.
 *
 * Use this when assessing exposure. Use {@link isProviderUsableForIssuance} when
 * deciding whether a *new* credential can be issued.
 */
export async function backsExistingCredentials(
  client: PublicClient,
  providers: ProviderRegistryLike,
  providerId: Hex,
): Promise<boolean> {
  return Boolean(
    await client.readContract({
      address: providers.address,
      abi: providers.abi,
      functionName: "backsExistingCredentials",
      args: [providerId],
    }),
  );
}

/** Can this provider attest a new credential right now? */
export async function isProviderUsableForIssuance(
  client: PublicClient,
  providers: ProviderRegistryLike,
  providerId: Hex,
): Promise<boolean> {
  return Boolean(
    await client.readContract({ address: providers.address, abi: providers.abi, functionName: "isActive", args: [providerId] }),
  );
}

/** Does a provider hold the current heartbeat? Monitoring signal only. */
export async function isProviderHealthy(
  client: PublicClient,
  providers: ProviderRegistryLike,
  providerId: Hex,
): Promise<boolean> {
  return Boolean(
    await client.readContract({ address: providers.address, abi: providers.abi, functionName: "isProviderHealthy", args: [providerId] }),
  );
}

/** List the providers a schema version admits. Bounded on-chain by MAX_PROVIDERS_PER_SCHEMA. */
export async function acceptedProvidersForSchema(
  client: PublicClient,
  schemas: { address: Address; abi: readonly unknown[] },
  credentialType: Hex,
  schemaVersion: number,
): Promise<Hex[]> {
  const list = await client.readContract({
    address: schemas.address,
    abi: schemas.abi,
    functionName: "acceptedProviders",
    args: [credentialType, schemaVersion],
  });
  return list as Hex[];
}

/**
 * Report a provider liveness check.
 *
 * Requires a signer. Monitoring jobs should use this from a dedicated operator
 * key, not from a holder or integrator key: it is a write path, and separating
 * keys means a compromised read-only integration cannot stall a provider's health.
 */
export async function reportHeartbeat(
  wallet: WalletClient,
  providers: ProviderRegistryLike,
  providerId: Hex,
): Promise<Hex> {
  const hash = await wallet.writeContract({
    address: providers.address,
    abi: providers.abi,
    functionName: "heartbeat",
    args: [providerId],
    chain: wallet.chain,
    account: wallet.account ?? null,
  });
  return hash;
}