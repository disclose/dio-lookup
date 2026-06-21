# dio-lookup

Pipe internet assets to [lookup.disclose.io](https://lookup.disclose.io) and get the right **security-disclosure contact** for each — as JSONL, built for recon pipelines.

Give it a domain, IP, ASN, URL, email, package, repo, container, cloud resource, mobile app, hardware, browser extension, or org name; get back the owner and where to report a vulnerability (security.txt, bug bounty program, VDP, PSIRT, national CERT).

```bash
subfinder -d example.com | httpx -silent | dio-lookup > contacts.jsonl
cat hosts.txt | dio-lookup -c 8
dio-lookup cloudflare.com npm:express gh:facebook/react
```

## Install

**With [Bun](https://bun.sh) (run from source):**

```bash
bun install -g dio-lookup        # or: git clone + bun link
```

**Prebuilt binary** (no runtime needed) — grab the right asset from [Releases](https://github.com/disclose/dio-lookup/releases), then:

```bash
chmod +x dio-lookup && sudo mv dio-lookup /usr/local/bin/
```

## Usage

```
dio-lookup [options] [asset ...]
cat hosts.txt | dio-lookup [options]

  -c, --concurrency N   parallel requests (default 5)
  -k, --key KEY         API key (raises rate limits); or set DIO_API_KEY
      --api URL         API endpoint (default https://lookup.disclose.io/api/lookup)
      --full            emit the full LookupResult instead of the compact summary
  -V, --version         print version
  -h, --help            help
```

One JSON object per asset on stdout. Compact form:

```json
{"input":"cloudflare.com","assetType":"domain","status":"complete","organization":"Cloudflare","jurisdiction":"US","contacts":[{"type":"security_txt","value":"https://www.cloudflare.com/.well-known/security.txt","confidence":"high"}]}
```

Pull just the reporting channels with `jq`:

```bash
cat hosts.txt | dio-lookup | jq -r 'select(.status=="complete") | "\(.input)\t\(.contacts[0].value)"'
```

## Notes

- **Free and anonymous.** A free API key only raises rate limits — request one by opening an issue on [lookup.disclose.io](https://github.com/disclose/lookup.disclose.io). Pass it with `-k` or `DIO_API_KEY`.
- Honors the API's `Retry-After` on 429 and retries transient failures.
- `--full` emits the complete `LookupResult` (attribution, contacts, resolution chain, data sources) — see the [OpenAPI spec](https://lookup.disclose.io/openapi.yaml).

A [disclose.io](https://disclose.io) project. MIT licensed.
