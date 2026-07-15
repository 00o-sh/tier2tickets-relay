import { describe, expect, it } from "vitest";
import { PRODUCTS, ipAllowed, matchProduct } from "../src/products.js";
import type { Env } from "../src/types.js";

const TIER2_IP = [...PRODUCTS.tier2!.ips][0]!;
const HUNTRESS_IP = "52.4.130.244";

/** A request carrying (or omitting) a CF-Connecting-IP header. */
function reqFrom(ip?: string): Request {
  const headers = ip ? { "CF-Connecting-IP": ip } : undefined;
  return new Request("https://haloapi.example.com/tickets", { headers });
}

/** Minimal Env carrying the allowlist vars (undefined => unset). */
function envWith(enforce?: string, enabledProducts?: string): Env {
  return { ENFORCE_IP_ALLOWLIST: enforce, ENABLED_PRODUCTS: enabledProducts } as unknown as Env;
}

describe("ipAllowed — fail closed (audit F2)", () => {
  it("ENFORCES when the var is unset (the key F2 fix)", () => {
    expect(ipAllowed(reqFrom(TIER2_IP), envWith(undefined))).toBe(true);
    expect(ipAllowed(reqFrom("9.9.9.9"), envWith(undefined))).toBe(false);
    expect(ipAllowed(reqFrom(undefined), envWith(undefined))).toBe(false); // absent header fails closed
  });

  it("ENFORCES on 'true' and any non-disabling value (incl. mixed case)", () => {
    for (const v of ["true", "True", "TRUE", "yes", "on", "1", "enforce"]) {
      expect(ipAllowed(reqFrom("9.9.9.9"), envWith(v))).toBe(false);
      expect(ipAllowed(reqFrom(TIER2_IP), envWith(v))).toBe(true);
    }
  });

  it("only disables on an explicit, normalized false / 0 / empty", () => {
    for (const v of ["false", "False", "  FALSE  ", "0", "", "   "]) {
      expect(ipAllowed(reqFrom("9.9.9.9"), envWith(v))).toBe(true);
    }
  });
});

describe("ENABLED_PRODUCTS gating", () => {
  it("defaults to tier2 alone — Huntress IPs are rejected until opted in", () => {
    expect(ipAllowed(reqFrom(TIER2_IP), envWith("true", undefined))).toBe(true);
    expect(ipAllowed(reqFrom(HUNTRESS_IP), envWith("true", undefined))).toBe(false);
    expect(ipAllowed(reqFrom(HUNTRESS_IP), envWith("true", ""))).toBe(false);
  });

  it("enables Huntress (exact IPs) only when listed", () => {
    for (const ip of [...PRODUCTS.huntress!.ips]) {
      expect(ipAllowed(reqFrom(ip), envWith("true", "tier2,huntress"))).toBe(true);
    }
    // tier2 still works alongside it.
    expect(ipAllowed(reqFrom(TIER2_IP), envWith("true", "tier2,huntress"))).toBe(true);
  });

  it("supports Huntress-only enablement (tier2 then rejected)", () => {
    expect(ipAllowed(reqFrom(HUNTRESS_IP), envWith("true", "huntress"))).toBe(true);
    expect(ipAllowed(reqFrom(TIER2_IP), envWith("true", "huntress"))).toBe(false);
  });

  it("accepts space- and comma-separated keys and ignores unknown ones", () => {
    for (const list of ["tier2 huntress", "tier2, huntress", "tier2,bogus,huntress"]) {
      expect(ipAllowed(reqFrom(HUNTRESS_IP), envWith("true", list))).toBe(true);
    }
    // A list of only unknown keys enables nothing -> fails closed.
    expect(ipAllowed(reqFrom(TIER2_IP), envWith("true", "bogus"))).toBe(false);
  });
});

describe("Huntress /28 CIDR ranges (when enabled)", () => {
  const ENABLED = envWith("true", "huntress");

  it("allows IPs inside the ranges and rejects those just outside", () => {
    // 4.150.82.176/28 -> 4.150.82.176 .. 4.150.82.191
    expect(ipAllowed(reqFrom("4.150.82.176"), ENABLED)).toBe(true);
    expect(ipAllowed(reqFrom("4.150.82.185"), ENABLED)).toBe(true);
    expect(ipAllowed(reqFrom("4.150.82.191"), ENABLED)).toBe(true);
    expect(ipAllowed(reqFrom("4.150.82.175"), ENABLED)).toBe(false);
    expect(ipAllowed(reqFrom("4.150.82.192"), ENABLED)).toBe(false);
    // 172.200.220.176/28 -> 172.200.220.176 .. 172.200.220.191
    expect(ipAllowed(reqFrom("172.200.220.176"), ENABLED)).toBe(true);
    expect(ipAllowed(reqFrom("172.200.220.191"), ENABLED)).toBe(true);
    expect(ipAllowed(reqFrom("172.200.220.175"), ENABLED)).toBe(false);
    expect(ipAllowed(reqFrom("172.200.220.192"), ENABLED)).toBe(false);
  });

  it("rejects a malformed CF-Connecting-IP", () => {
    for (const bad of ["not-an-ip", "4.150.82", "999.1.1.1", "4.150.82.176.1"]) {
      expect(ipAllowed(reqFrom(bad), ENABLED)).toBe(false);
    }
  });
});

describe("matchProduct — returns which product matched (for future routing)", () => {
  it("identifies the matching enabled product", () => {
    expect(matchProduct(reqFrom(TIER2_IP), envWith("true", "tier2,huntress"))?.key).toBe("tier2");
    expect(matchProduct(reqFrom(HUNTRESS_IP), envWith("true", "tier2,huntress"))?.key).toBe("huntress");
    expect(matchProduct(reqFrom("4.150.82.180"), envWith("true", "tier2,huntress"))?.key).toBe(
      "huntress",
    );
  });

  it("returns null when no enabled product matches", () => {
    expect(matchProduct(reqFrom(HUNTRESS_IP), envWith("true", "tier2"))).toBeNull();
    expect(matchProduct(reqFrom("9.9.9.9"), envWith("true", "tier2,huntress"))).toBeNull();
    expect(matchProduct(reqFrom(undefined), envWith("true", "tier2,huntress"))).toBeNull();
  });
});
