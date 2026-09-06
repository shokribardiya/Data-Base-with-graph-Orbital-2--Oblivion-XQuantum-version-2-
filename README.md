<img width="2048" height="768" alt="hero-wave-dark" src="https://github.com/user-attachments/assets/c23f3f9b-c12a-4f2b-83d5-0d2360e4ee4e" />
## Data-Base-with-graph-Orbital-2--Oblivion-XQuantum-version-2


# Oblivion Orbital: A Single-File Approach to Unifying Knowledge Graphs, Code Intelligence, and Operational Control

*Engineering notes from Team Oblivion. Lead developer: Bardiya Shokri.*

Most platforms that try to do what Oblivion Orbital does — knowledge management, an in-browser development environment, and an operations control plane — end up as three separate services stitched together with brittle integration code. Each piece accumulates its own deployment story, its own auth model, its own way of failing. The team's decision here was the opposite: collapse the whole system into one process, one schema, and one entry point, and let internal boundaries be enforced by module structure rather than network hops. Whether or not that's the right call for every deployment, it's a deliberate one, and it shapes almost every design decision downstream.

## The problem: knowledge work is fragmented by tooling, not by nature

A researcher importing a batch of documents, a developer debugging a script against that research, and an administrator deciding who gets to see either — these are usually treated as three different products with three different login screens. Oblivion Orbital treats them as three views onto the same underlying store. A single SQLite database backs a knowledge graph, a session/role table, and an operational registry, and a single HTTP handler routes all three. The bet is that co-location beats orchestration when the alternative is gluing together a graph database, an LSP server, and an admin panel that all need to agree on who's authenticated.

## Knowledge graph engine

At the core sits a graph store: nodes carry a label, spatial coordinates for layout, a computed community assignment and betweenness score, and a `source_file` provenance tag; edges carry weight and the same provenance tag. Every sentence ingested during an import is retained and linked back to the nodes it mentions, so a node's detail view isn't just "here are its neighbors" but "here is the actual textual evidence for why this node exists." Search runs through SQLite's FTS layer with automatic prefix-matching, so a partial query still surfaces relevant terms without the caller needing to hand-craft a match expression.

The provenance modeling deserves particular attention because it's what makes the system's teardown path safe. Deleting an imported file doesn't just remove sentences — it walks every node's comma-separated source list, strips the deleted file out, and only removes the node itself once no source file still claims it. That's a small design choice, but it's the difference between "delete" meaning "orphan a bunch of half-attributed data" and "delete" meaning what a user expects it to mean.

## Code intelligence, without a hard dependency on any one tool

The editor embedded in the dashboard is backed by a diagnostics and completion pipeline modeled on the Language Server Protocol's core verbs — but it doesn't require an LSP server to be running. If `pyflakes` is present, diagnostics come from it; if not, the system falls back to compiling the buffer with `ast`/`compile` and reporting syntax errors directly. If `jedi` is present, completions are semantic; if not, a keyword-and-scope-based fallback still returns something usable. `pluggy` is used the same way for the importer hook system: when it's available, new file-format importers register as proper hook implementations against a declared spec; when it isn't, a no-op decorator keeps the same call sites working.

This is the part of the codebase that reads most like an engineering decision rather than a feature list: every "smart" capability has a dumb, dependency-free twin, and the banner printed at startup tells the operator exactly which mode each subsystem landed in. A team running this in an air-gapped or restricted environment loses precision, not function.

## The data-control plane

Authentication is username/password with PBKDF2-HMAC-SHA256 hashing (200,000 iterations) and constant-time comparison — unremarkable, and correctly so; this is not a place to be clever. Sessions are opaque tokens held server-side with an 8-hour TTL. Roles gate specific endpoints (`admin` is required to view the audit log, create users, delete files, or reset a graph), and every sensitive action is written to an append-only audit table with timestamp, actor, action, detail, and source IP.

Layered on top of that is a two-tier access-code scheme distinct from per-user accounts: a full-access code with no expiry, and a trial code that opens a rolling window on first use. Both are checked against salted hashes embedded in the source rather than plaintext values, so reading the file doesn't leak working credentials — a small but meaningful hardening step for a single-file, easily-copied artifact.

## Platform Store: borrowing the control-panel vocabulary

The most distinctive architectural choice is the "Platform Store" — a generic entity table partitioned into six categories: Environments, Products & Releases, Release Channels, Teams & Permissions, Change Management, and Upgrades & Plans. This mirrors the reference-data sections found in operations-control tooling built for managing software across many independent environments — the same conceptual split between *where things run*, *what's running*, *how it gets promoted*, *who can touch it*, and *what changed and why*. Any create, update, or delete against this store automatically feeds a notifications endpoint, so the dashboard's activity feed is a side effect of the schema rather than a separately maintained log.

Building this as one generic table instead of six bespoke ones is a pragmatic trade: less code, one CRUD path, one permission check — at the cost of losing category-specific validation at the database layer. For an internal tool prioritizing iteration speed, that trade is defensible; for a system managing consequential change-control decisions, it's worth watching as usage grows.

## Where operators should stay alert

In the interest of giving this the same measured treatment we'd want from any technical write-up: the `/api/run` and `/api/notebook` endpoints execute submitted code directly via `exec()` in the server's own process, with no sandboxing, resource limits, or filesystem/network isolation. That's an acceptable posture for a trusted, single-operator or small-team deployment behind the existing auth layer — it is not a posture that should be exposed to untrusted users or the open internet. Any team adopting this pattern more broadly should plan to move code execution into an isolated subprocess or container before widening access.

## Why this shape works

Oblivion Orbital isn't trying to out-engineer purpose-built graph databases, IDEs, or deployment platforms individually. It's making a bet that for a single team's internal tooling, one coherent process with honest fallbacks beats three well-specialized ones that don't talk to each other. The graceful-degradation pattern, the provenance-aware deletion logic, and the audit-everything default are the parts of that bet that are already paying for themselves; the unsandboxed execution path is the part that comes with a bill attached the moment the deployment target changes.



For **Oblivion Orbital**, nothing is strictly required beyond Python's standard library — the whole app (HTTP server, SQLite storage, knowledge graph, auth, dashboard) runs out of the box with just:

```
python oblivion_orbital.py
```

**Optional (recommended) packages** — only needed to unlock the higher-quality code-intelligence features; without them the app automatically falls back to stdlib-based alternatives:

```
pip install pyflakes jedi pluggy
```

| Package | What it upgrades | Fallback if missing |
|---|---|---|
| `pyflakes` | Accurate diagnostics/linting in the editor | `ast`/`compile()`-based syntax checking |
| `jedi` | Semantic, context-aware code completion | Simple keyword/scope-based completion |
| `pluggy` | Proper plugin/hook system for import formats | No-op decorator, same call sites still work |

So: install those three if you want the full "smart editor" experience; skip them entirely if you just want the knowledge graph, auth, and dashboard running with zero dependencies.
This system is designed for data control and pattern recognition. This is the second version; to access the software for a ten-day demo, please visit the website below and send a message to the email address listed there.You go to the contact section in website and send an email with the request, along with a paragraph about what you want to use it for and a certificate of your work.