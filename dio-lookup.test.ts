import { test, expect, describe, afterEach } from "bun:test";
import { parseArgs, lookupOne, VERSION } from "./dio-lookup.ts";

// A response recorded verbatim from lookup.disclose.io on 2026-07-05. It pins the
// contract the compact mapping depends on: assetType, status, attribution.{organization,
// jurisdiction}, and contacts[].{type,value,confidence}. The `liveContract` test below
// re-checks these keys against the real API so a service-side drift fails the suite.
const RECORDED = {
  input: "cloudflare.com",
  assetType: "domain",
  status: "complete",
  requestId: "req_recorded",
  attribution: { confidence: "high", organization: "Cloudflare", jurisdiction: "US" },
  contacts: [
    { type: "bug_bounty", value: "https://www.cloudflare.com/disclosure/", confidence: "high", source: "diodb", label: "Cloudflare (Bounty)", verified: true },
    { type: "security_txt", value: "https://www.cloudflare.com/abuse/", confidence: "high", source: "security-txt", verified: true },
  ],
};

const opts = (over: Partial<Parameters<typeof lookupOne>[1]> = {}) =>
  ({ concurrency: 1, api: "http://127.0.0.1:0", full: false, inputs: [], ...over }) as any;

let servers: ReturnType<typeof Bun.serve>[] = [];
function serve(fetch: (req: Request) => Response | Promise<Response>) {
  const s = Bun.serve({ port: 0, fetch });
  servers.push(s);
  return `http://127.0.0.1:${s.port}/api/lookup`;
}
afterEach(() => { servers.forEach((s) => s.stop(true)); servers = []; });

describe("parseArgs", () => {
  test("defaults", () => {
    const o = parseArgs([]) as any;
    expect(o.concurrency).toBe(5);
    expect(o.full).toBe(false);
    expect(o.inputs).toEqual([]);
    expect(o.api).toContain("lookup.disclose.io");
  });
  test("collects positional assets", () => {
    const o = parseArgs(["cloudflare.com", "npm:express"]) as any;
    expect(o.inputs).toEqual(["cloudflare.com", "npm:express"]);
  });
  test("flags: concurrency, key, api, full", () => {
    const o = parseArgs(["-c", "8", "-k", "SECRET", "--api", "http://x/y", "--full"]) as any;
    expect(o.concurrency).toBe(8);
    expect(o.apiKey).toBe("SECRET");
    expect(o.api).toBe("http://x/y");
    expect(o.full).toBe(true);
  });
  test("non-positive or garbage concurrency falls back to the default (5)", () => {
    // `0 || 5` -> 5 (zero is falsy); NaN || 5 -> 5. Either way a sane worker count.
    expect((parseArgs(["-c", "0"]) as any).concurrency).toBe(5);
    expect((parseArgs(["-c", "nope"]) as any).concurrency).toBe(5);
    expect((parseArgs(["-c", "8"]) as any).concurrency).toBe(8);
  });
  test("--version / --help are recognized", () => {
    expect(parseArgs(["--version"])).toEqual({ version: true });
    expect(parseArgs(["-h"])).toEqual({ help: true });
  });
  test("unknown flag falls back to help", () => {
    expect(parseArgs(["--bogus"])).toEqual({ help: true });
  });
});

describe("lookupOne compact mapping", () => {
  test("maps a recorded-real body to the compact summary", async () => {
    const api = serve(() => Response.json(RECORDED));
    const out = (await lookupOne("cloudflare.com", opts({ api }))) as any;
    expect(out.input).toBe("cloudflare.com");
    expect(out.assetType).toBe("domain");
    expect(out.status).toBe("complete");
    expect(out.organization).toBe("Cloudflare");
    expect(out.jurisdiction).toBe("US");
    expect(out.contacts).toHaveLength(2);
    // Compact form drops source/label/verified, keeps type/value/confidence only.
    expect(out.contacts[0]).toEqual({ type: "bug_bounty", value: "https://www.cloudflare.com/disclosure/", confidence: "high" });
    expect(Object.keys(out.contacts[0])).toEqual(["type", "value", "confidence"]);
  });
  test("missing fields degrade to null, not crash", async () => {
    const api = serve(() => Response.json({ input: "x", contacts: [] }));
    const out = (await lookupOne("x", opts({ api }))) as any;
    expect(out.assetType).toBeNull();
    expect(out.organization).toBeNull();
    expect(out.contacts).toEqual([]);
  });
  test("--full returns the whole body untouched", async () => {
    const api = serve(() => Response.json(RECORDED));
    const out = (await lookupOne("cloudflare.com", opts({ api, full: true }))) as any;
    expect(out.requestId).toBe("req_recorded");
    expect(out.attribution.organization).toBe("Cloudflare");
  });
  test("sends the API key as a Bearer header when set", async () => {
    let seen = "";
    const api = serve((req) => { seen = req.headers.get("authorization") ?? ""; return Response.json(RECORDED); });
    await lookupOne("cloudflare.com", opts({ api, apiKey: "K123" }));
    expect(seen).toBe("Bearer K123");
  });
  test("privacy: request body contains ONLY the input asset", async () => {
    let body: any = null;
    const api = serve(async (req) => { body = await req.json(); return Response.json(RECORDED); });
    await lookupOne("github.com", opts({ api }));
    expect(Object.keys(body)).toEqual(["input"]);
    expect(body.input).toBe("github.com");
  });
});

describe("lookupOne resilience", () => {
  test("honors a 429 then succeeds on retry", async () => {
    let n = 0;
    const api = serve(() => {
      n++;
      if (n === 1) return new Response("rate limited", { status: 429, headers: { "retry-after": "1" } });
      return Response.json(RECORDED);
    });
    const out = (await lookupOne("cloudflare.com", opts({ api }))) as any;
    expect(n).toBe(2);
    expect(out.organization).toBe("Cloudflare");
  }, 10_000);

  test("returns an {error} object after exhausting retries", async () => {
    const out = (await lookupOne("x", opts({ api: "http://127.0.0.1:1/nope" }))) as any;
    expect(out.error).toBeTruthy();
    expect(out.input).toBe("x");
  }, 10_000);
});

describe("live contract (skips offline)", () => {
  test("real API still returns the fields the mapping depends on", async () => {
    let body: any;
    try {
      const res = await fetch("https://lookup.disclose.io/api/lookup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: "cloudflare.com" }),
        signal: AbortSignal.timeout(15_000),
      });
      body = await res.json();
    } catch {
      console.warn("[live contract] skipped — API unreachable");
      return;
    }
    expect(body).toHaveProperty("assetType");
    expect(body).toHaveProperty("status");
    expect(body.attribution).toHaveProperty("organization");
    expect(Array.isArray(body.contacts)).toBe(true);
    for (const c of body.contacts.slice(0, 3)) {
      expect(c).toHaveProperty("type");
      expect(c).toHaveProperty("value");
      expect(c).toHaveProperty("confidence");
    }
  }, 20_000);
});

describe("CLI exit codes (subprocess)", () => {
  test("no input assets exits 2", async () => {
    const proc = Bun.spawn(["bun", "dio-lookup.ts"], {
      cwd: import.meta.dir, stdin: "pipe", stdout: "ignore", stderr: "ignore",
    });
    proc.stdin.end();
    expect(await proc.exited).toBe(2);
  });
  test("--version prints the version and exits 0", async () => {
    const proc = Bun.spawn(["bun", "dio-lookup.ts", "--version"], { cwd: import.meta.dir, stdout: "pipe" });
    const out = (await new Response(proc.stdout).text()).trim();
    expect(await proc.exited).toBe(0);
    expect(out).toBe(VERSION);
  });
  test("a successful lookup against a mock exits 0 with JSONL", async () => {
    const api = serve(() => Response.json(RECORDED));
    const proc = Bun.spawn(["bun", "dio-lookup.ts", "--api", api, "cloudflare.com"], {
      cwd: import.meta.dir, stdout: "pipe", stderr: "ignore",
    });
    const out = (await new Response(proc.stdout).text()).trim();
    expect(await proc.exited).toBe(0);
    const obj = JSON.parse(out);
    expect(obj.organization).toBe("Cloudflare");
  });
});
