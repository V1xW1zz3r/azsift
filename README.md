# azsift

A CLI tool that maps resources in an Azure subscription into related bundles by template deployments, ownership, property references, and creation timestamps, alongside RBAC and Managed Identity visibility.

Built on top of the Azure CLI (`az`) for security research and auditing—especially spotting ungrouped or unlinked resources (or "shadow resources", as I'd like to call them) and checking what identities in a subscription can access. Use it only on subscriptions you are authorized to assess.

## Requirements

- [Go](https://go.dev/) 1.21+
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az`)
- Azure CLI `resource-graph` extension (for property references, Managed Identities, and deployment grouping; without it, `azsift` falls back to timestamps and `az resource list` ownership only):
  ```bash
  az extension add --name resource-graph
  ```
- **Reader** on the subscription is enough. Anything your role can't read is shown as unknown.

## Build

```bash
git clone https://github.com/v1xW1zz3r/azsift.git
cd azsift
go build -o azsift .
```

Or install directly to `$GOPATH/bin`:

```bash
go install github.com/v1xW1zz3r/azsift@latest
```

## Usage

Make sure you are logged in (`az login`), or pass `-login`:

```bash
./azsift                     # Scan current subscription
./azsift -sub <id-or-name>   # Target a specific subscription
./azsift -all                # Dump all bundles non-interactively
./azsift -since 72h          # Highlight resources created in the last 3 days
./azsift -rbac=false         # Skip RBAC lookups
```

### Snapshots & Offline Input

```bash
./azsift -save snap.json     # Scan and save resources, graph, deployments & RBAC
./azsift -f snap.json        # Inspect a snapshot offline
```

Raw outputs can be loaded instead with `-listf`, `-graphf`, `-deployf`, and `-rbacf` (either a full `RBACData` JSON from a snapshot, or plain `az role assignment list -o json`).

> Snapshots contain full resource properties, deployment records, role assignments, and your caller identity. They are written owner-only (`0600`), but treat them as sensitive and don't commit them.

## Interactive Commands

| Command | Action |
|---|---|
| `1,3` / `2-4` | Inspect bundle(s) by number |
| `l` / `st` | List bundles / show subscription, RBAC, and filter status |
| `/term` | Filter by name, type, resource group, or creator (`/` or `/clear` resets). Also `/new`, `/mi` (`/identity`), `/rg:<name>` |
| `r` | RBAC overview & Managed Identities across bundles |
| `r perms` | Permissions per assigned role (`r perms full` for all actions) |
| `r <bundle>` | Your effective access & Managed Identities on a bundle (`r <bundle> full` for all actions) |
| `s [num\|name]` | Switch subscription (online, 2+ subscriptions; runs `az account set`) |
| `refresh` | Re-scan the current subscription |
| `a` / `u` | Dump all visible bundles / show ungrouped resources |
| `?` / `q` | Help / quit |

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `-sub <id\|name>` | current account | Subscription to scan |
| `-login` | off | Run `az login` first |
| `-save <file>` | | Save full scan snapshot to file |
| `-f <file>` | | Inspect a saved snapshot offline |
| `-listf <file>` | | Load `az resource list -o json` from file |
| `-graphf <file>` | | Load `az graph query -o json` from file |
| `-deployf <file>` | | Load deployment query JSON from file |
| `-rbacf <file>` | | Load RBAC JSON or `az role assignment list -o json` from file |
| `-window <dur>` | `30m` | Max gap to cluster resources created together (`0` disables) |
| `-subwindow <dur>` | `15m` | Max gap to bracket sub-resources (`0` disables) |
| `-depth <n>` | `2` | Reference hops to follow from an anchor |
| `-deep` | on | Discover deeper sub-resources (blob containers and subnets) |
| `-deployments` | on | Group by ARM/Bicep deployments |
| `-rbac` | on | RBAC and Managed Identity lookups when online |
| `-all` | off | Dump all bundles and exit (non-interactive) |
| `-since <time\|dur>` | last run | Mark newer resources (`2026-10-01`, `72h`) |
| `-no-state` | off | Don't read or write the last-run state file |
| `-no-color` | off | Disable ANSI colors (also honors `NO_COLOR`) |

Turn booleans off with `=false`, e.g. `-deep=false`. Note that `-f` and `-listf` cannot be combined.

## Reading the output

| Marker | Meaning |
|---|---|
| `~2026-10-13 08:28:26` | Inferred time, not a real creation time (containers use last-modified; subnets use the VNet's creation time) |
| `[shared]` | Belongs to more than one bundle |
| `[→ bundle #3 name (type)]` | Reference into a resource owned by another bundle |
| `● new` | Created after the last run or `-since` (`● new inside`: a member is new) |
| `[MI:2]`, `(3 hyp)` | In the list: managed identities in the bundle / members matched by timing only |
| right-hand bracket | Child resources within `-subwindow` of each other: probably one operation |
| `[hypothesis: …]` | Matched by timing only |

Bundles are anchored by ARM/Bicep deployments (2+ resources), major workload types (VMs, AKS, Web Apps, Data Factory, Synapse, Databricks, ML Workspaces) or top-level owner resources, and temporal batches (2+ resources created together in the same resource group).

Within a bundle, members are grouped from strongest evidence to weakest: template deployments, parent/child ownership, `managedBy` ownership, property references (including attached user-assigned identities), and timing. Timing only groups resources in the same resource group (and by the same creator, when known), and is always labeled a hypothesis.

## RBAC & Managed Identities

Shows the roles held by each bundle's system and user-assigned identities, your own role assignments (direct, inherited, and via groups when Microsoft Graph access allows), and your effective access on a bundle: `read`, `write`, `delete`, `assign RBAC`, and `data-plane`.

Role definitions for `r perms` are fetched on demand. When something can't be read, it says so (e.g., `unknown (Reader required)`, `denied (requires Microsoft.Authorization/permissions/read)`). PIM-eligible and deny assignments aren't queried.

## What it runs

Read-only against Azure (`az account`, `resource list`, `graph query`, `rest --method get`, `role assignment list`, `role definition list`).

Locally it runs `az login` if needed, `az account set` when you switch subscriptions, reads your access token only to extract your object ID (`oid`), and writes `azsift/state.json` (last scan per subscription; disable with `-no-state`) in your user config directory. Snapshots are written only with `-save`.

## Limitations

- Azure keeps no creation time for blob containers or subnets, hence the `~` times.
- You only see what your role can read, and only the control plane: no blob contents, secrets, or table rows.
- Timing-based links are guesses.
- Deployment grouping, property references, and Managed Identity discovery require Resource Graph.

All timestamps are UTC. Table width follows the `COLUMNS` environment variable (`COLUMNS - 2`, capped at 140; default 116).

## Need more features? Not satisfied?

You are highly encouraged to suggest features, report bugs, or open a pull request/issue thingie... idk :)