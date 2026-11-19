# Development

```bash
(cd web && npm ci && npm run build)
cargo test
cargo run -- --bind 127.0.0.1:18080
```

With a kubeconfig, Gjallarhorn reads that cluster. `--fixtures fixtures/demo.json` serves a made-up homelab instead, with no cluster at all; the screenshots in these docs come from it. `python3 fixtures/generate_demo.py` writes a fresh one, with publication dates relative to today.

For frontend work, run the backend on port 18080 and `npm run dev` in `web/`; Vite proxies `/api` to it.

The aggregation is in `src/snapshot.rs`. `build()` takes the raw reports and returns the snapshot, without touching the network, and the tests feed it report fixtures shaped like the Trivy Operator's output. The report shapes are in `src/raw.rs`; the HTTP server is in `src/main.rs`.

The frontend is Svelte 5 in `web/src`, one file per page in `web/src/pages`. The release binary embeds `web/dist`, so build the frontend before `cargo build --release`.
