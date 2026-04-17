<p align="center">
  <img src="docs/banner.svg" alt="Secret Sweep — Dispersal Wolves" width="100%">
</p>

# Secret Sweep

**Find credentials before they leave the working tree.**

Scans files or staged Git changes using credential patterns and entropy signals, with redacted output and allowlisting.

## Start

```console
node src/secret-sweep.js scan .
```

Run the command with `--help` for every option. The tool works locally, collects no telemetry, and supports machine-readable output where applicable.

## Principles

- **Local first.** Host data stays on the host unless you explicitly configure a webhook.
- **Safe by default.** Inspection is read-only and mutation requires a deliberate command.
- **Small contract.** The tool solves one defensive job and reports its limits plainly.
- **Scriptable.** Stable exit codes and structured output make automation practical.

## Platform

The initial release targets Linux. Portable behavior is also tested on Windows where the underlying operating-system facilities allow it. See [the threat model](docs/threat-model.md) for trust boundaries and non-goals.

## Development

This repository uses **Node.js** without runtime dependencies. `.secret-sweep.json` can allowlist reviewed fingerprints and paths without exposing the corresponding secret.

```console
npm ci
npm test
npm run lint
```

## License

[MIT](LICENSE) © Dispersal Wolves.
