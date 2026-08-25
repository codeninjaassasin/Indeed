# Indeed Job Notifier

Desktop app that watches Indeed searches and posts new postings to Mattermost.
One worker thread (and browser) per role, all sharing a single rotating proxy.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/playwright install chromium

cp .env.example .env        # add your Mattermost webhook URL
.venv/bin/python indeed_notifier.py
```

## Usage

```bash
python indeed_notifier.py            # launch the UI
python indeed_notifier.py --nogui    # watch loop, uses saved config.json
python indeed_notifier.py --nogui --once
python indeed_notifier.py --nogui --reseed   # rebuild state, fire no alerts
python indeed_notifier.py --checkip  # show egress IP, test Indeed
```

## Filters

Edited in the UI and saved to `config.json`:

- **Roles** — one search phrase per line; each gets its own worker and browser.
- **Region** — US remote or worldwide remote.
- **Application** — all postings, or Easy Apply only.
- **Job type** — full-time / part-time / contract.
- **Title must include / must NOT include** — comma- or newline-separated terms.
  Indeed pads a thin result page with loosely-related postings, so titles are
  filtered locally too. Matching is case-insensitive and whole-word, with
  punctuation folded, so `full stack` also matches `Full-Stack`. Exclude wins
  over include.

## Proxies

Free proxy lists are fetched and validated in the background. Only SOCKS5
relays reliably reach Indeed, so the validation batch is weighted toward them.

Any proxy that actually returns job cards is promoted to `safe_proxies.json`.
On a captcha or timeout the next proxy comes from that safe list first, and
only once it is exhausted does discovery take over. Proven proxies are not
evicted until failures exceed successes by a margin, so one bad run does not
discard a good relay.

Free proxies are unreliable against Indeed's bot protection. Expect blocked
cycles; a paid residential proxy is the fix if you need consistency.

## Internal CA

If the Mattermost host is served by a private CA (e.g. Caddy's local
authority), `requests` will fail TLS verification even when browsers and
`curl` succeed. Rather than disabling verification, export the root and build
a bundle:

```bash
mkdir -p certs
security find-certificate -a -c "<CA common name>" -p \
  ~/Library/Keychains/login.keychain-db > certs/caddy_root.pem
.venv/bin/python -c "import certifi,pathlib; \
  p=pathlib.Path('certs/ca_bundle.pem'); \
  p.write_text(pathlib.Path(certifi.where()).read_text()+'\n'+ \
               pathlib.Path('certs/caddy_root.pem').read_text())"
```

Then set `MATTERMOST_CA_BUNDLE=certs/ca_bundle.pem` in `.env`. Verify with:

```bash
openssl s_client -connect <host>:443 -CAfile certs/ca_bundle.pem
```

## State

- `seen_jobs.json` — job id to first-seen timestamp; duplicates are impossible
  and pruning drops the oldest entries.
- `safe_proxies.json` — proven proxies with success/failure counts.
- `config.json` — filter settings.

All three are gitignored; they are per-machine runtime state.
