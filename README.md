# azsift

A CLI tool that maps resources in an Azure subscription into related bundles by template deployments, parent/child ownership, property references, and creation timestamps, alongside RBAC and Managed Identity visibility.

Built on top of the Azure CLI (`az`) for security research and auditing, especially spotting ungrouped or unlinked resources and checking what identities in a subscription can access.

## Requirements

- [Go](https://go.dev/) 1.21+
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az`)
- Azure CLI `resource-graph` extension (recommended for property references, Managed Identities, and deployment grouping):
  ```bash
  az extension add --name resource-graph
  ```

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
./azsift                     # Scan current subscription (interactive)
./azsift -sub <id-or-name>   # Target a specific subscription
./azsift -login              # Run 'az login' before scanning
./azsift -all                # Dump all bundles non-interactively
```

### Saving & Inspecting Offline Snapshots

```bash
./azsift -save snap.json     # Scan online and save resources, graph, deployments & RBAC
./azsift -f snap.json        # Inspect a saved snapshot offline
```

You can also load raw saved `az` JSON outputs directly with `-listf`, `-graphf`, `-deployf`, and `-rbacf`. Run `./azsift -h` for all flags.

## Interactive Commands

| Command | Action |
|---|---|
| `1,3` / `2-4` | Inspect bundle(s) by number |
| `l` | List bundles |
| `st` | Show subscription, RBAC, and filter status |
| `/term` | Filter bundles (`/` or `/clear` to reset, `/new`, `/mi`, `rg:<name>`) |
| `r` | RBAC overview & Managed Identities across bundles |
| `r perms` | List permissions per assigned role (`r perms full` for all actions) |
| `r <bundle>` | Check effective access & Managed Identities on a bundle |
| `s` | Switch subscription |
| `refresh` | Re-scan current subscription |
| `a` / `u` | Dump all visible bundles / show ungrouped resources |
| `?` / `q` | Help / quit |

## Notes

- All timestamps are displayed in UTC.
- By default, the last scan timestamp per subscription is saved under your user config directory (`azsift/state.json`) to highlight newly created resources on the next run. Pass `-no-state` to disable this.

## Need more features? Not satisfied?
You are highly encouraged to suggest features, report bugs, or open a pull request/issue thingie... idk :)