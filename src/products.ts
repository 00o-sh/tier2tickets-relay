import { breadcrumb } from "./log.js";
import type { Env } from "./types.js";

/**
 * A source product whose Halo integration posts into this relay. Access is
 * gated by matching the request's `CF-Connecting-IP` against the product's exact
 * IPs or CIDR ranges. `key` is the token used in the ENABLED_PRODUCTS env var.
 */
export interface Product {
  key: string;
  label: string;
  ips: Set<string>; // exact source IPs
  cidrs: string[]; // IPv4 CIDR ranges ("a.b.c.d/len")
}

/**
 * Registry of known source products. To onboard a product: add its exact IPs
 * and/or CIDR ranges here, then enable it at runtime via ENABLED_PRODUCTS in
 * wrangler.toml. NOTE: allowlisting a product's IPs is only the doorman — the
 * downstream ticket-building path (buildHaloDescription / HDB report parsing) is
 * still Tier2/Helpdesk-Buttons-shaped, so a newly enabled product needs its own
 * field handling before it produces correct Gorelo tickets. `matchProduct`
 * returns the matched product precisely so that handling can branch on it later.
 */
export const PRODUCTS: Record<string, Product> = {
  // Tier2Tickets / Helpdesk Buttons cloud — the original integration.
  tier2: {
    key: "tier2",
    label: "Tier2Tickets / Helpdesk Buttons",
    ips: new Set(["34.202.14.153", "3.209.57.193"]),
    cidrs: [],
  },
  // Huntress — additional source IPs + /28 ranges. Opt-in via ENABLED_PRODUCTS.
  huntress: {
    key: "huntress",
    label: "Huntress",
    ips: new Set(["52.4.130.244", "34.205.224.75", "184.72.103.99", "107.21.187.4"]),
    cidrs: ["4.150.82.176/28", "172.200.220.176/28"],
  },
};

/** Product(s) enabled when ENABLED_PRODUCTS is unset/empty (backward-compatible default). */
const DEFAULT_ENABLED = ["tier2"];

/** Parse a dotted-quad IPv4 string to a 32-bit unsigned int, or null if malformed. */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** True if `ip` falls within the `a.b.c.d/len` IPv4 CIDR range. */
export function ipInCidr(ip: string, cidr: string): boolean {
  const [base, lenStr] = cidr.split("/");
  const prefix = Number(lenStr);
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base ?? "");
  if (ipInt === null || baseInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  if (prefix === 0) return true;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/**
 * Resolve ENABLED_PRODUCTS (comma/space-separated product keys) to Product
 * objects. Unset/empty defaults to Tier2 alone so behavior is unchanged until
 * other products are explicitly opted in. Unknown keys are ignored with a
 * breadcrumb so a typo can't silently widen or narrow access.
 */
export function enabledProducts(env: Env): Product[] {
  const raw = (env.ENABLED_PRODUCTS ?? "").trim();
  const keys = raw ? raw.split(/[\s,]+/).filter(Boolean) : DEFAULT_ENABLED;
  const out: Product[] = [];
  for (const k of keys) {
    const p = PRODUCTS[k.toLowerCase()];
    if (p) out.push(p);
    else breadcrumb(`ENABLED_PRODUCTS: unknown product "${k}" — ignored`);
  }
  return out;
}

/**
 * The enabled product whose allowlist contains the request's `CF-Connecting-IP`,
 * or null if none match (or the header is absent — which fails closed). Returns
 * the Product rather than a boolean so callers can later branch ticket handling
 * on which product a request originated from.
 */
export function matchProduct(request: Request, env: Env): Product | null {
  const ip = request.headers.get("CF-Connecting-IP") ?? "";
  if (!ip) return null;
  for (const p of enabledProducts(env)) {
    if (p.ips.has(ip) || p.cidrs.some((c) => ipInCidr(ip, c))) return p;
  }
  return null;
}

/**
 * True if the request is from an allowlisted source IP (or the allowlist is
 * explicitly disabled). Fails closed (audit F2): the allowlist is ENFORCED by
 * default. Only an explicit, normalized `"false"`, `"0"`, or `""` disables it —
 * an unset var, `"true"`, `"True"`, or any other value enforces. Enforcement
 * matches `CF-Connecting-IP` against the exact IPs and CIDR ranges of the
 * currently ENABLED_PRODUCTS; the header is Cloudflare-controlled and an absent
 * header already fails closed (it matches no product).
 */
export function ipAllowed(request: Request, env: Env): boolean {
  const raw = env.ENFORCE_IP_ALLOWLIST;
  if (raw !== undefined) {
    const flag = raw.trim().toLowerCase();
    if (flag === "false" || flag === "0" || flag === "") return true; // explicitly disabled
  }
  return matchProduct(request, env) !== null;
}
