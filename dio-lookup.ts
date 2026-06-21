#!/usr/bin/env bun
/**
 * dio-lookup — pipe internet assets to lookup.disclose.io, get security
 * disclosure contacts back as JSONL.
 *
 * Built for recon pipelines:
 *   subfinder -d example.com | httpx -silent | dio-lookup
 *   cat hosts.txt | dio-lookup --concurrency 8 > contacts.jsonl
 *   dio-lookup cloudflare.com npm:express gh:facebook/react
 *
 * Each input asset (domain, IP, ASN, URL, email, package, repo, container,
 * cloud resource, mobile app, hardware, extension, org name) becomes one JSON
 * object on stdout. Anonymous + free; an optional API key raises rate limits.
 */

const VERSION = '0.1.0';
const DEFAULT_API = 'https://lookup.disclose.io/api/lookup';

interface Options {
  concurrency: number;
  api: string;
  apiKey?: string;
  full: boolean;
  inputs: string[];
}

function parseArgs(argv: string[]): Options | { help: true } | { version: true } {
  const o: Options = { concurrency: 5, api: DEFAULT_API, full: false, inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') return { help: true };
    if (a === '-V' || a === '--version') return { version: true };
    else if (a === '-c' || a === '--concurrency') o.concurrency = Math.max(1, parseInt(argv[++i] ?? '5', 10) || 5);
    else if (a === '--api') o.api = argv[++i] ?? DEFAULT_API;
    else if (a === '-k' || a === '--key') o.apiKey = argv[++i];
    else if (a === '--full') o.full = true;
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
  -c, --concurrency N   parallel requests (default 5)
  -k, --key KEY         API key (raises rate limits); or set DIO_API_KEY
      --api URL         API endpoint (default ${DEFAULT_API})
      --full            emit the full LookupResult instead of the compact summary
  -V, --version         print version
  -h, --help            this help

OUTPUT
  One JSON object per asset on stdout (JSONL). Compact form:
  {"input","assetType","status","organization","jurisdiction","contacts":[{type,value,confidence}]}

EXAMPLES
  dio-lookup cloudflare.com
  subfinder -d example.com | httpx -silent | dio-lookup -c 8 > contacts.jsonl
  echo npm:express | dio-lookup --full | jq .

A disclose.io project — https://lookup.disclose.io`;

async function readStdinLines(): Promise<string[]> {
  if (process.stdin.isTTY) return [];
  const text = await new Response(Bun.stdin.stream()).text();
  return text.split('\n').map(l => l.trim()).filter(Boolean);
}

interface Contact { type: string; value: string; confidence: string }
interface LookupResult {
  input: string; assetType?: string; status?: string;
  attribution?: { organization?: string; jurisdiction?: string };
  contacts?: Contact[];
}

async function lookupOne(input: string, o: Options): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', 'User-Agent': `dio-lookup/${VERSION}` };
  const key = o.apiKey ?? process.env.DIO_API_KEY;
  if (key) headers['Authorization'] = `Bearer ${key}`;

  // Up to 3 attempts, honoring Retry-After on 429.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(o.api, { method: 'POST', headers, body: JSON.stringify({ input }) });
      if (res.status === 429) {
        const wait = Math.min(30, parseInt(res.headers.get('retry-after') ?? '2', 10) || 2);
        await Bun.sleep(wait * 1000);
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
async function run(inputs: string[], o: Options): Promise<number> {
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

const parsed = parseArgs(process.argv.slice(2));
if ('help' in parsed) { console.log(HELP); process.exit(0); }
if ('version' in parsed) { console.log(VERSION); process.exit(0); }

const stdinInputs = await readStdinLines();
const inputs = [...parsed.inputs, ...stdinInputs];
if (inputs.length === 0) { console.error('no input assets (pass as args or pipe via stdin); --help for usage'); process.exit(2); }

const failures = await run(inputs, parsed);
process.exit(failures > 0 && failures === inputs.length ? 1 : 0);
