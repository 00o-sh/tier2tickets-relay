import { createExecutionContext, env, fetchMock, waitOnExecutionContext } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index.js";
import { initSchema } from "../src/db.js";

const GORELO = "https://api.usw.gorelo.io";
const KEY = "test-expected-key";

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});
afterEach(() => fetchMock.assertNoPendingInterceptors());
afterAll(() => fetchMock.deactivate());

/** Seed the mirror and mark it synced so the first-press bootstrap is skipped. */
async function seedSynced(devices: Array<[string, string, number, number, string]>): Promise<void> {
  await initSchema(env.DB);
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM devices`),
    env.DB.prepare(`DELETE FROM client_domains`),
    env.DB.prepare(`DELETE FROM sync_meta`),
  ]);
  const stmts = devices.map(([host, upn, cid, loc, agent]) =>
    env.DB
      .prepare(`INSERT INTO devices (hostname, upn, client_id, location_id, agent_id) VALUES (?,?,?,?,?)`)
      .bind(host, upn, cid, loc, agent),
  );
  stmts.push(
    env.DB.prepare(`INSERT INTO sync_meta (key, value) VALUES ('last_sync', ?)`).bind("2026-01-01T00:00:00Z"),
  );
  await env.DB.batch(stmts);
}

function post(body: string, contentType: string, extraHeaders: Record<string, string> = {}): Request {
  return new Request(`${GORELO}/`, {
    method: "POST",
    headers: { "content-type": contentType, "X-API-Key": KEY, ...extraHeaders },
    body,
  });
}

async function dispatch(req: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

describe("ticket create handler", () => {
  beforeEach(async () => {
    await seedSynced([["pc-01", "user@corp.com", 10, 100, "agent-abc"]]);
  });

  it("known machine -> 201 + ticket number, correct command mapping (JSON)", async () => {
    const pool = fetchMock.get(GORELO);
    pool
      .intercept({ path: (p) => p.startsWith("/v1/contacts"), method: "GET" })
      .reply(200, JSON.stringify([{ id: 55, primaryEmail: "user@corp.com", clientId: 10 }]));

    let posted: Record<string, unknown> | undefined;
    pool
      .intercept({ path: "/v1/tickets", method: "POST" })
      .reply(201, (opts) => {
        posted = JSON.parse(opts.body as string);
        return JSON.stringify({ ticketNumber: "INC-42" });
      });

    const body = JSON.stringify({
      name: "Jane Doe",
      email: "user@corp.com",
      subject: "Printer down",
      message: "It won't print.\n\n[[hdb host=PC-01.corp.local mac=AA:BB:CC:DD:EE:FF ip=10.0.0.5]]",
    });
    const res = await dispatch(post(body, "application/json"));

    expect(res.status).toBe(201);
    expect(await res.text()).toBe("INC-42");

    expect(posted).toMatchObject({
      title: "Printer down",
      createdByName: "Jane Doe",
      clientId: 10,
      locationId: 100,
      contactId: 55,
      groupId: 7,
      typeId: 3,
      priorityId: 2,
      sourceId: 4,
      agentAssetIds: ["agent-abc"],
      sendTicketCreatedEmail: false,
    });
    const description = String(posted?.description ?? "");
    expect(description).toContain("It won't print.");
    expect(description).not.toContain("[[hdb");
    expect(description).toContain("host: pc-01");
    expect(description).toContain("mac: AA:BB:CC:DD:EE:FF");
  });

  it("form-encoded body maps the same way", async () => {
    const pool = fetchMock.get(GORELO);
    pool
      .intercept({ path: (p) => p.startsWith("/v1/contacts"), method: "GET" })
      .reply(200, JSON.stringify([]));
    let posted: Record<string, unknown> | undefined;
    pool.intercept({ path: "/v1/tickets", method: "POST" }).reply(201, (opts) => {
      posted = JSON.parse(opts.body as string);
      return JSON.stringify({ number: "9001" });
    });

    const form = new URLSearchParams({
      name: "Bob",
      email: "user@corp.com",
      subject: "VPN",
      msg: "cannot connect [[hdb host=pc-01 ip=1.2.3.4]]",
    });
    const res = await dispatch(post(form.toString(), "application/x-www-form-urlencoded"));

    expect(res.status).toBe(201);
    expect(await res.text()).toBe("9001");
    expect(posted).toMatchObject({ title: "VPN", clientId: 10, agentAssetIds: ["agent-abc"] });
  });

  it("unknown machine -> catch-all client with a triage note", async () => {
    const pool = fetchMock.get(GORELO);
    pool
      .intercept({ path: (p) => p.startsWith("/v1/contacts"), method: "GET" })
      .reply(200, JSON.stringify([]));
    let posted: Record<string, unknown> | undefined;
    pool.intercept({ path: "/v1/tickets", method: "POST" }).reply(201, (opts) => {
      posted = JSON.parse(opts.body as string);
      return JSON.stringify({ id: 12345 });
    });

    const body = JSON.stringify({
      name: "Stranger",
      email: "stranger@nowhere.test",
      subject: "Whatever",
      message: "help [[hdb host=ghost mac=x ip=y]]",
    });
    const res = await dispatch(post(body, "application/json"));

    expect(res.status).toBe(201);
    expect(await res.text()).toBe("12345");
    expect(posted).toMatchObject({ clientId: 999, contactId: null, agentAssetIds: [] });
    expect(String(posted?.description)).toContain("[triage]");
  });

  it("Gorelo create failure -> 502", async () => {
    const pool = fetchMock.get(GORELO);
    pool
      .intercept({ path: (p) => p.startsWith("/v1/contacts"), method: "GET" })
      .reply(200, JSON.stringify([]));
    pool.intercept({ path: "/v1/tickets", method: "POST" }).reply(500, "boom");

    const body = JSON.stringify({ email: "user@corp.com", subject: "x", message: "y [[hdb host=pc-01]]" });
    const res = await dispatch(post(body, "application/json"));
    expect(res.status).toBe(502);
    expect(await res.text()).toContain("gorelo");
  });

  it("wrong X-API-Key -> 401 (no upstream calls)", async () => {
    const body = JSON.stringify({ email: "user@corp.com", subject: "x", message: "y" });
    const res = await dispatch(post(body, "application/json", { "X-API-Key": "wrong" }));
    expect(res.status).toBe(401);
  });

  it("enforces the IP allowlist when enabled", async () => {
    const prev = env.ENFORCE_IP_ALLOWLIST;
    (env as { ENFORCE_IP_ALLOWLIST: string }).ENFORCE_IP_ALLOWLIST = "true";
    try {
      const body = JSON.stringify({ email: "user@corp.com", subject: "x", message: "y" });
      // No CF-Connecting-IP header -> not allowlisted.
      const res = await dispatch(post(body, "application/json"));
      expect(res.status).toBe(403);
    } finally {
      (env as { ENFORCE_IP_ALLOWLIST: string }).ENFORCE_IP_ALLOWLIST = prev;
    }
  });

  it("allows a whitelisted Tier2 source IP", async () => {
    const prev = env.ENFORCE_IP_ALLOWLIST;
    (env as { ENFORCE_IP_ALLOWLIST: string }).ENFORCE_IP_ALLOWLIST = "true";
    const pool = fetchMock.get(GORELO);
    pool.intercept({ path: (p) => p.startsWith("/v1/contacts"), method: "GET" }).reply(200, "[]");
    pool.intercept({ path: "/v1/tickets", method: "POST" }).reply(201, JSON.stringify({ ticketNumber: "OK-1" }));
    try {
      const body = JSON.stringify({ email: "user@corp.com", subject: "x", message: "y [[hdb host=pc-01]]" });
      const res = await dispatch(post(body, "application/json", { "CF-Connecting-IP": "34.202.14.153" }));
      expect(res.status).toBe(201);
      expect(await res.text()).toBe("OK-1");
    } finally {
      (env as { ENFORCE_IP_ALLOWLIST: string }).ENFORCE_IP_ALLOWLIST = prev;
    }
  });
});

describe("admin + health", () => {
  it("POST /admin/sync requires the key", async () => {
    const res = await dispatch(
      new Request(`${GORELO}/admin/sync`, { method: "POST", headers: { "X-API-Key": "nope" } }),
    );
    expect(res.status).toBe(401);
  });

  it("GET /health returns ok", async () => {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`${GORELO}/health`), env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });
});
