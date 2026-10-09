#!/usr/bin/env bun
/**
 * dio-lookup — pipe internet assets to lookup.disclose.io, get security
 * disclosure contacts back as JSONL.
 *
 * Built for recon pipelines:
 *   subfinder -d example.com | httpx -silent | dio-lookup
 *   cat hosts.txt | dio-lookup --concurrency 4 > contacts.jsonl
 *   dio-lookup cloudflare.com npm:express gh:facebook/react
 *
 * Each input asset (domain, IP, ASN, URL, email, package, repo, container,
 * cloud resource, mobile app, hardware, extension, org name) becomes one JSON
 * object on stdout. Anonymous + free; an optional API key raises rate limits.
 */

const VERSION = '0.2.1';
const DEFAULT_CONCURRENCY = 4;
const REQUEST_TIMEOUT_MS = 45_000;
const DEFAULT_API = 'https://lookup.disclose.io/api/lookup';

interface Options {
  concurrency: number;
  api: string;
  apiKey?: string;
  full: boolean;
  nuclei: boolean;
  inputs: string[];
}

export function parseArgs(argv: string[]): Options | { help: true } | { version: true } {
  const o: Options = { concurrency: DEFAULT_CONCURRENCY, api: DEFAULT_API, full: false, nuclei: false, inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') return { help: true };
    if (a === '-V' || a === '--version') return { version: true };
    else if (a === '-c' || a === '--concurrency') o.concurrency = Math.max(1, parseInt(argv[++i] ?? '', 10) || DEFAULT_CONCURRENCY);
    else if (a === '--api') o.api = argv[++i] ?? DEFAULT_API;
    else if (a === '-k' || a === '--key') o.apiKey = argv[++i];
    else if (a === '--full') o.full = true;
    else if (a === '--nuclei') o.nuclei = true;
    else if (a.startsWith('-')) { process.stderr.write(`unknown flag: ${a}\n`); return { help: true }; }
    else o.inputs.push(a);
  }
  return o;
}

const HELP = `dio-lookup ${VERSION} — security-disclosure contacts for any internet asset

USAGE
  dio-lookup [options] [asset ...]
  cat hosts.txt | dio-lookup [options]

OPTIONS
  -c, --concurrency N   parallel requests (default 4; the service runs ~8 lookups
                        at once for everyone, so more mostly earns 503s)
  -k, --key KEY         API key (raises rate limits); or set DIO_API_KEY
      --api URL         API endpoint (default ${DEFAULT_API})
      --full            emit the full LookupResult instead of the compact summary
      --nuclei          treat stdin as nuclei -jsonl output: extract the scanned
                        host from each finding, de-duplicate, then enrich each
  -V, --version         print version
  -h, --help            this help

OUTPUT
  One JSON object per asset on stdout (JSONL). Compact form:
  {"input","assetType","status","organization","jurisdiction","contacts":[{type,value,confidence}]}

EXAMPLES
  dio-lookup cloudflare.com
  subfinder -d example.com | httpx -silent | dio-lookup -c 4 > contacts.jsonl
  echo npm:express | dio-lookup --full | jq .
  nuclei -u example.com -jsonl | dio-lookup --nuclei    # enrich each scanned host

  # equivalent bridge without --nuclei (works with any dio-lookup):
  nuclei -u example.com -jsonl | jq -r '.host' | sort -u | dio-lookup

A disclose.io project — https://lookup.disclose.io`;

async function readStdinLines(): Promise<string[]> {
  if (process.stdin.isTTY) return [];
  const text = await new Response(Bun.stdin.stream()).text();
  return text.split('\n').map(l => l.trim()).filter(Boolean);
}

export function hostFrom(v: unknown): string | undefined {
  if (typeof v !== 'string' || !v) return undefined;
  try { return new URL(v.includes('://') ? v : `http://${v}`).hostname || undefined; }
  catch { return undefined; }
}

// --nuclei: stdin is `nuclei -jsonl` (one finding OBJECT per line, not bare hosts).
// Pull the scanned host from each finding and de-duplicate, so a scan producing many
// findings across many hosts collapses to one lookup per unique host — which keeps the
// call volume (and the API rate limit) sane. Non-JSON lines (banners, blanks) are skipped.
export function extractNucleiHosts(lines: string[]): string[] {
  const seen = new Set<string>();
  const hosts: string[] = [];
  for (const line of lines) {
    let f: Record<string, unknown>;
    try { f = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
    let host =
      (typeof f.host === 'string' && f.host ? f.host : undefined) ??
      hostFrom(f['matched-at']) ?? hostFrom(f.url) ?? hostFrom(f.matched) ??
      (typeof f.ip === 'string' ? f.ip : undefined);
    if (!host) continue;
    // Strip :port without mangling a bare IPv6 (which has multiple colons).
    const bracketed = host.match(/^\[(.+?)\](?::\d+)?$/);        // [ipv6] or [ipv6]:port
    if (bracketed) host = bracketed[1];
    else if (/^[^:]+:\d+$/.test(host)) host = host.slice(0, host.lastIndexOf(':')); // host:port
    if (!seen.has(host)) { seen.add(host); hosts.push(host); }
  }
  return hosts;
}

interface Contact { type: string; value: string; confidence: string }
interface LookupResult {
  input: string; assetType?: string; status?: string;
  attribution?: { organization?: string; jurisdiction?: string };
  contacts?: Contact[];
}

export async function lookupOne(input: string, o: Options): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'User-Agent': `dio-lookup/${VERSION}` };
  const key = o.apiKey ?? process.env.DIO_API_KEY;
  if (key) headers['Authorization'] = `Bearer ${key}`;

  // Up to 3 attempts, honoring Retry-After on 429 (rate limit) and 503 (the
  // service is at capacity). A lookup can take ~30s, so the request timeout sits
  // above that: giving up early leaves the server working for nobody.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(o.api, {
        method: 'POST', headers, body: JSON.stringify({ input }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 429 || res.status === 503) {
        const wait = Math.min(30, parseInt(res.headers.get('retry-after') ?? '2', 10) || 2);
        // Up to 1s of jitter so a pool of workers shed together does not retry together.
        await Bun.sleep(wait * 1000 + Math.floor(Math.random() * 1000));
        continue;
      }
      const body = await res.json() as LookupResult;
      if (o.full) return body as unknown as Record<string, unknown>;
      return {
        input,
        assetType: body.assetType ?? null,
        status: body.status ?? null,
        organization: body.attribution?.organization ?? null,
        jurisdiction: body.attribution?.jurisdiction ?? null,
        contacts: (body.contacts ?? []).map(c => ({ type: c.type, value: c.value, confidence: c.confidence })),
      };
    } catch (err) {
      if (attempt === 2) return { input, error: String(err).slice(0, 200) };
      await Bun.sleep(1000);
    }
  }
  return { input, error: 'exhausted retries' };
}

// Bounded-concurrency worker pool over the input list, preserving nothing about
// order (recon pipelines don't need it) — emit as each completes.
export async function run(inputs: string[], o: Options): Promise<number> {
  let idx = 0;
  let failures = 0;
  const out = (obj: Record<string, unknown>) => {
    if (obj.error) failures++;
    process.stdout.write(JSON.stringify(obj) + '\n');
  };
  const worker = async () => {
    while (idx < inputs.length) {
      const i = idx++;
      out(await lookupOne(inputs[i], o));
    }
  };
  await Promise.all(Array.from({ length: Math.min(o.concurrency, inputs.length) }, worker));
  return failures;
}

export { VERSION, HELP };
export type { Options, LookupResult, Contact };

// Only run the CLI when executed directly (`bun dio-lookup.ts`), not when imported
// by the test suite. This keeps parseArgs/lookupOne/run unit-testable in isolation.
if (import.meta.main) {
  const parsed = parseArgs(process.argv.slice(2));
  if ('help' in parsed) { console.log(HELP); process.exit(0); }
  if ('version' in parsed) { console.log(VERSION); process.exit(0); }

  const stdinLines = await readStdinLines();
  const stdinInputs = parsed.nuclei ? extractNucleiHosts(stdinLines) : stdinLines;
  if (parsed.nuclei && stdinLines.length) {
    process.stderr.write(`[dio-lookup] --nuclei: ${stdinLines.length} finding line(s) -> ${stdinInputs.length} unique host(s)\n`);
  }
  const inputs = [...parsed.inputs, ...stdinInputs];
  if (inputs.length === 0) { console.error('no input assets (pass as args or pipe via stdin); --help for usage'); process.exit(2); }

  const failures = await run(inputs, parsed);
  process.exit(failures > 0 && failures === inputs.length ? 1 : 0);
}
