package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// resource types that own a cluster of resources
var anchorTypes = map[string]bool{
	"microsoft.machinelearningservices/workspaces": true,
	"microsoft.containerservice/managedclusters":   true,
	"microsoft.databricks/workspaces":              true,
	"microsoft.synapse/workspaces":                 true,
	"microsoft.datafactory/factories":              true,
	"microsoft.web/sites":                          true,
	"microsoft.compute/virtualmachines":            true,
}

type IdentityInfo struct {
	Type                   string `json:"type"`
	PrincipalID            string `json:"principalId"`
	TenantID               string `json:"tenantId"`
	UserAssignedIdentities map[string]struct {
		PrincipalID string `json:"principalId"`
		ClientID    string `json:"clientId"`
	} `json:"userAssignedIdentities"`
}

type Resource struct {
	ID         string        `json:"id"`
	Key        string        `json:"key"`
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	RG         string        `json:"rg"`
	Location   string        `json:"location"`
	CreatedBy  string        `json:"createdBy,omitempty"`
	ManagedBy  string        `json:"managedBy,omitempty"`
	Created    time.Time     `json:"created"`
	Changed    time.Time     `json:"changed"`
	Identity   *IdentityInfo `json:"identity,omitempty"`
	Props      interface{}   `json:"props,omitempty"`
	TimeApprox bool          `json:"timeApprox,omitempty"` // (parent's time / lastModified) due to the storage account thingy
}

func isAnchor(r *Resource, ix *Index) bool {
	if r == nil {
		return false
	}
	if anchorTypes[strings.ToLower(r.Type)] {
		return true
	}
	return ix != nil && len(ix.Owned[r.Key]) > 0 && !ix.HasOwner[r.Key]
}

type AccountUser struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Subscription struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	IsDefault bool        `json:"isDefault"`
	State     string      `json:"state"`
	TenantID  string      `json:"tenantId"`
	User      AccountUser `json:"user"`
}

// basically "az resource list -o json" command and parse stuff
type listItem struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	ResourceGroup string `json:"resourceGroup"`
	Location      string `json:"location"`
	ManagedBy     string `json:"managedBy"`
	CreatedTime   string `json:"createdTime"`
	ChangedTime   string `json:"changedTime"`
	SystemData    *struct {
		CreatedBy string `json:"createdBy"`
	} `json:"systemData"`
}

// resource graph with properties + identity
type graphItem struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	ResourceGroup string        `json:"resourceGroup"`
	Location      string        `json:"location"`
	ManagedBy     string        `json:"managedBy"`
	Identity      *IdentityInfo `json:"identity"`
	Properties    interface{}   `json:"properties"`
	SystemData    *struct {
		CreatedBy      string `json:"createdBy"`
		CreatedAt      string `json:"createdAt"`
		LastModifiedAt string `json:"lastModifiedAt"`
	} `json:"systemData"`
}

// ARM deployments from resource graph
type deploymentItem struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	Properties    struct {
		Timestamp       string `json:"timestamp"`
		Duration        string `json:"duration"`
		OutputResources []struct {
			ID string `json:"id"`
		} `json:"outputResources"`
	} `json:"properties"`
}

// RBAC & permissions models

type RoleAssignment struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Scope              string `json:"scope"`
	RoleDefinitionID   string `json:"roleDefinitionId"`
	RoleDefinitionName string `json:"roleDefinitionName"`
	PrincipalID        string `json:"principalId"`
	PrincipalName      string `json:"principalName"`
	PrincipalType      string `json:"principalType"`
	Condition          string `json:"condition"`
}

type PermissionBlock struct {
	Actions        []string `json:"actions"`
	NotActions     []string `json:"notActions"`
	DataActions    []string `json:"dataActions"`
	NotDataActions []string `json:"notDataActions"`
}

type RoleDefinition struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	RoleName         string            `json:"roleName"`
	RoleType         string            `json:"roleType"`
	Description      string            `json:"description"`
	AssignableScopes []string          `json:"assignableScopes"`
	Permissions      []PermissionBlock `json:"permissions"`
}

type EffectivePermResult struct {
	Status string            `json:"status"` // "ok", "denied", "error", "unavailable"
	Error  string            `json:"error,omitempty"`
	Scope  string            `json:"scope,omitempty"`
	Blocks []PermissionBlock `json:"blocks,omitempty"`
}

type RBACData struct {
	Caller          AccountUser                     `json:"caller"`
	CallerOID       string                          `json:"callerOid,omitempty"`
	UserRolesStatus string                          `json:"userRolesStatus"` // "ok", "denied", "error", "unavailable"
	UserRolesErr    string                          `json:"userRolesErr,omitempty"`
	UserRoles       []RoleAssignment                `json:"userRoles,omitempty"`
	AllRolesStatus  string                          `json:"allRolesStatus"` // "ok", "denied", "error", "unavailable"
	AllRolesErr     string                          `json:"allRolesErr,omitempty"`
	ByPrincipal     map[string][]RoleAssignment     `json:"byPrincipal,omitempty"`
	Effective       EffectivePermResult             `json:"effective"`
	RoleDefs        map[string]*RoleDefinition      `json:"roleDefs,omitempty"`
	BundlePerms     map[string]*EffectivePermResult `json:"bundlePerms,omitempty"`
	mu              sync.Mutex
}

type Snapshot struct {
	Version      int              `json:"version"`
	CapturedAt   time.Time        `json:"capturedAt"`
	Subscription Subscription     `json:"subscription"`
	List         []listItem       `json:"list"`
	Graph        []graphItem      `json:"graph"`
	Deployments  []deploymentItem `json:"deployments,omitempty"`
	Subresources []*Resource      `json:"subresources,omitempty"`
	RBAC         *RBACData        `json:"rbac,omitempty"`
}

type ManagedIDRef struct {
	Kind        string // sys or usr assigned
	PrincipalID string
	Label       string
	UsedBy      string
	ResourceID  string
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, s); err != nil {
			return time.Time{}
		}
	}
	return t.UTC()
}

// merge joins list and graph items on lowercased ARM ID
func merge(list []listItem, graph []graphItem) []*Resource {
	byKey := map[string]*Resource{}
	var out []*Resource
	get := func(id string) *Resource {
		k := strings.ToLower(id)
		if r, ok := byKey[k]; ok {
			return r
		}
		r := &Resource{ID: id, Key: k}
		byKey[k] = r
		out = append(out, r)
		return r
	}
	for _, it := range list {
		if it.ID == "" {
			continue
		}
		r := get(it.ID)
		r.Name, r.Type, r.RG, r.Location, r.ManagedBy = it.Name, it.Type, it.ResourceGroup, it.Location, it.ManagedBy
		r.Created, r.Changed = parseTime(it.CreatedTime), parseTime(it.ChangedTime)
		if it.SystemData != nil && it.SystemData.CreatedBy != "" {
			r.CreatedBy = it.SystemData.CreatedBy
		}
	}
	for _, it := range graph {
		if it.ID == "" {
			continue
		}
		r := get(it.ID)
		if r.Name == "" {
			r.Name = it.Name
		}
		if r.Type == "" {
			r.Type = it.Type
		}
		if r.RG == "" {
			r.RG = it.ResourceGroup
		}
		if r.Location == "" {
			r.Location = it.Location
		}
		if r.ManagedBy == "" {
			r.ManagedBy = it.ManagedBy
		}
		if it.SystemData != nil {
			if r.CreatedBy == "" && it.SystemData.CreatedBy != "" {
				r.CreatedBy = it.SystemData.CreatedBy
			}
			if r.Created.IsZero() && it.SystemData.CreatedAt != "" {
				r.Created = parseTime(it.SystemData.CreatedAt)
			}
			if r.Changed.IsZero() && it.SystemData.LastModifiedAt != "" {
				r.Changed = parseTime(it.SystemData.LastModifiedAt)
			}
		}
		if it.Identity != nil {
			r.Identity = it.Identity
		}
		r.Props = it.Properties
	}
	return out
}

// This thing extracts subnets from VNets and blob containers from Storage Accounts
func expandSubresources(sub string, rs []*Resource, deep, online bool) ([]*Resource, []*Resource) {
	var extra []*Resource
	existing := make(map[string]bool, len(rs))
	for _, r := range rs {
		existing[r.Key] = true
	}

	var storageAccts []*Resource
	for _, r := range rs {
		props, ok := r.Props.(map[string]interface{})
		if !ok {
			continue
		}

		// VNets -> subnets from properties
		if strings.EqualFold(r.Type, "microsoft.network/virtualnetworks") {
			if subnets, ok := props["subnets"].([]interface{}); ok {
				for _, sn := range subnets {
					sm, ok := sn.(map[string]interface{})
					if !ok {
						continue
					}
					id, _ := sm["id"].(string)
					name, _ := sm["name"].(string)
					k := strings.ToLower(id)
					if id != "" && !existing[k] {
						existing[k] = true
						extra = append(extra, &Resource{
							ID:         id,
							Key:        k,
							Name:       name,
							Type:       "Microsoft.Network/virtualNetworks/subnets",
							RG:         r.RG,
							Location:   r.Location,
							Created:    r.Created,
							Props:      sm,
							TimeApprox: true,
						})
					}
				}
			}
		}

		if deep && online && strings.EqualFold(r.Type, "microsoft.storage/storageaccounts") {
			storageAccts = append(storageAccts, r)
		}
	}

	// Storage Accounts -> blob containers
	var onlineExtra []*Resource
	if len(storageAccts) > 0 {
		perAcct := make([][]*Resource, len(storageAccts))
		jobs := make(chan int, len(storageAccts))
		for i := range storageAccts {
			jobs <- i
		}
		close(jobs)

		workers := min(8, len(storageAccts))
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					r := storageAccts[idx]
					url := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers?api-version=2023-01-01", sub, r.RG, r.Name)
					b, err := azRun("rest", "--method", "get", "--url", url)
					if err != nil {
						continue
					}
					var res struct {
						Value []struct {
							ID         string                 `json:"id"`
							Name       string                 `json:"name"`
							Properties map[string]interface{} `json:"properties"`
						} `json:"value"`
					}
					if json.Unmarshal(b, &res) != nil {
						continue
					}
					for _, c := range res.Value {
						if c.ID == "" {
							continue
						}
						var ct time.Time
						if lm, ok := c.Properties["lastModifiedTime"].(string); ok {
							ct = parseTime(lm)
						}
						if ct.IsZero() {
							ct = r.Created
						}
						perAcct[idx] = append(perAcct[idx], &Resource{
							ID:         c.ID,
							Key:        strings.ToLower(c.ID),
							Name:       c.Name,
							Type:       "Microsoft.Storage/storageAccounts/blobServices/containers",
							RG:         r.RG,
							Location:   r.Location,
							Created:    ct,
							Props:      c.Properties,
							TimeApprox: true,
						})
					}
				}
			}()
		}
		wg.Wait()

		for _, items := range perAcct {
			for _, item := range items {
				if !existing[item.Key] {
					existing[item.Key] = true
					extra = append(extra, item)
					onlineExtra = append(onlineExtra, item)
				}
			}
		}
	}

	return append(rs, extra...), onlineExtra
}

// relationships

type Edge struct {
	To   string
	Kind string // "ref", "child" or "managed"
	Path string // JSON path of the reference, for "ref" edges
}

type Index struct {
	Res      map[string]*Resource
	Refs     map[string][]Edge // resource -> resources its properties point at
	Owned    map[string][]Edge // owner -> child / managed resources
	HasOwner map[string]bool   // resources that have a parent or managedBy owner
	OwnerOf  map[string]string // child key -> owner key
}

// parentKey strips the last type/name pair from a nested resource ID
func parentKey(k string) string {
	const marker = "/providers/"
	i := strings.LastIndex(k, marker)
	if i < 0 {
		return ""
	}
	parts := strings.Split(k[i+len(marker):], "/")
	if (len(parts)-1)%2 != 0 || len(parts)-1 <= 2 {
		return ""
	}
	return k[:i+len(marker)] + strings.Join(parts[:len(parts)-2], "/")
}

func (ix *Index) resolve(id string) string {
	for k := strings.ToLower(strings.TrimRight(id, "/")); k != ""; k = parentKey(k) {
		if _, ok := ix.Res[k]; ok {
			return k
		}
	}
	return ""
}

// rootOf walks owner links up to the resource that heads the bundle holding key
func (ix *Index) rootOf(key string) *Resource {
	for i := 0; i < 10; i++ {
		o := ix.OwnerOf[key]
		if o == "" {
			break
		}
		key = o
	}
	return ix.Res[key]
}

func walk(v interface{}, path string, fn func(path, s string)) {
	switch t := v.(type) {
	case string:
		fn(path, t)
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(t[k], path+"."+k, fn)
		}
	case []interface{}:
		for _, x := range t {
			walk(x, path+"[]", fn)
		}
	}
}

func buildIndex(rs []*Resource) *Index {
	ix := &Index{
		Res:      make(map[string]*Resource, len(rs)),
		Refs:     map[string][]Edge{},
		Owned:    map[string][]Edge{},
		HasOwner: map[string]bool{},
		OwnerOf:  map[string]string{},
	}
	for _, r := range rs {
		ix.Res[r.Key] = r
	}
	for _, r := range rs {
		seen := map[string]bool{}
		addRef := func(targetID, path string) {
			to := ix.resolve(targetID)
			if to != "" && to != r.Key && !seen[to] {
				seen[to] = true
				ix.Refs[r.Key] = append(ix.Refs[r.Key], Edge{To: to, Kind: "ref", Path: path})
			}
		}
		walk(r.Props, "properties", func(path, s string) {
			if strings.HasPrefix(strings.ToLower(s), "/subscriptions/") {
				addRef(s, path)
			}
		})
		if r.Identity != nil && len(r.Identity.UserAssignedIdentities) > 0 {
			uKeys := make([]string, 0, len(r.Identity.UserAssignedIdentities))
			for k := range r.Identity.UserAssignedIdentities {
				uKeys = append(uKeys, k)
			}
			sort.Strings(uKeys)
			for _, uID := range uKeys {
				addRef(uID, "identity.userAssignedIdentities")
			}
		}
		if p := parentKey(r.Key); p != "" {
			if resolvedParent := ix.resolve(p); resolvedParent != "" {
				ix.Owned[resolvedParent] = append(ix.Owned[resolvedParent], Edge{To: r.Key, Kind: "child"})
				ix.HasOwner[r.Key] = true
				ix.OwnerOf[r.Key] = resolvedParent
			}
		}
		if r.ManagedBy != "" {
			if m := ix.resolve(r.ManagedBy); m != "" && m != r.Key {
				ix.Owned[m] = append(ix.Owned[m], Edge{To: r.Key, Kind: "managed"})
				ix.HasOwner[r.Key] = true
				ix.OwnerOf[r.Key] = m
			}
		}
	}
	return ix
}

// grouping services and subresources

type Member struct {
	R          *Resource
	Why        string
	Hypothesis string
	Kind       string // deploy, child, managed, ref, batch or hyp
	Via        string
	Elsewhere  bool
	Root       *Resource
}

type Group struct {
	Anchor  *Resource
	Members []Member
}

func buildGroups(ix *Index, rs []*Resource, deployments []deploymentItem, depth int, window time.Duration) ([]*Group, []*Resource) {
	assigned := map[string]int{}
	var groups []*Group

	// ARM Template Deployments
	for _, dep := range deployments {
		var matched []*Resource
		seenOutput := map[string]bool{}
		for _, out := range dep.Properties.OutputResources {
			if out.ID == "" {
				continue
			}
			if to := ix.resolve(out.ID); to != "" && !seenOutput[to] {
				seenOutput[to] = true
				matched = append(matched, ix.Res[to])
			}
		}
		if len(matched) < 2 {
			continue
		}
		anchor := &Resource{
			ID:       dep.ID,
			Key:      strings.ToLower(dep.ID),
			Name:     dep.Name,
			Type:     "Microsoft.Resources/deployments",
			RG:       dep.ResourceGroup,
			Created:  parseTime(dep.Properties.Timestamp),
			Location: "deployment",
		}
		g := &Group{Anchor: anchor}
		for _, m := range matched {
			g.Members = append(g.Members, Member{
				R:    m,
				Why:  fmt.Sprintf("deployed by ARM/Bicep template %s", dep.Name),
				Kind: "deploy",
				Via:  dep.Name,
			})
			assigned[m.Key]++
		}
		assigned[anchor.Key]++
		groups = append(groups, g)
	}

	// Anchor Groups
	for _, a := range rs {
		if !isAnchor(a, ix) {
			continue
		}
		g := &Group{Anchor: a}
		seen := map[string]bool{a.Key: true}
		type item struct {
			key string
			d   int
		}
		queue := []item{{a.Key, 0}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			curName := ix.Res[cur.key].Name
			for _, e := range ix.Owned[cur.key] {
				if seen[e.To] {
					continue
				}
				seen[e.To] = true
				why := "child of " + curName
				if e.Kind == "managed" {
					why = "managed by " + curName
				}
				g.Members = append(g.Members, Member{R: ix.Res[e.To], Why: why, Kind: e.Kind, Via: curName})
				queue = append(queue, item{e.To, cur.d})
			}
			if cur.d < depth {
				for _, e := range ix.Refs[cur.key] {
					if seen[e.To] {
						continue
					}
					seen[e.To] = true
					elsewhere := isAnchor(ix.Res[e.To], ix) || ix.HasOwner[e.To]
					var root *Resource
					if elsewhere {
						root = ix.rootOf(e.To)
					}
					g.Members = append(g.Members, Member{
						R:         ix.Res[e.To],
						Why:       fmt.Sprintf("referenced by %s via %s", curName, e.Path),
						Kind:      "ref",
						Via:       curName,
						Elsewhere: elsewhere,
						Root:      root,
					})
					if !elsewhere {
						queue = append(queue, item{e.To, cur.d + 1})
					}
				}
			}
		}
		if len(g.Members) > 0 || anchorTypes[strings.ToLower(a.Type)] {
			assigned[a.Key]++
			for _, m := range g.Members {
				assigned[m.R.Key]++
			}
			groups = append(groups, g)
		}
	}

	// Temporal Batch Clustering (sounds badass ngl)
	if window > 0 {
		byRG := map[string][]*Resource{}
		for _, r := range rs {
			if assigned[r.Key] > 0 || isAnchor(r, ix) || r.Created.IsZero() {
				continue
			}
			byRG[strings.ToLower(r.RG)] = append(byRG[strings.ToLower(r.RG)], r)
		}

		for rgKey, rgRes := range byRG {
			if len(rgRes) < 2 {
				continue
			}
			sort.SliceStable(rgRes, func(i, j int) bool { return rgRes[i].Created.Before(rgRes[j].Created) })

			var cluster []*Resource
			flushCluster := func() {
				if len(cluster) >= 2 {
					first := cluster[0]
					anchor := &Resource{
						ID:        fmt.Sprintf("/subscriptions/synthetic/resourceGroups/%s/batches/%s", first.RG, first.Created.Format("20060102-150405")),
						Key:       fmt.Sprintf("batch:%s:%s", rgKey, first.Created.Format(time.RFC3339)),
						Name:      fmt.Sprintf("Batch in %s", first.RG),
						Type:      "Deployment/Batch",
						RG:        first.RG,
						Location:  first.Location,
						Created:   first.Created,
						CreatedBy: first.CreatedBy,
					}
					g := &Group{Anchor: anchor}
					for _, cr := range cluster {
						why := fmt.Sprintf("created together in %s (within %s)", first.RG, fmtDur(window))
						if cr.CreatedBy != "" {
							why += " by " + cr.CreatedBy
						}
						g.Members = append(g.Members, Member{
							R:          cr,
							Why:        why,
							Hypothesis: "temporal cluster",
							Kind:       "batch",
						})
						assigned[cr.Key]++
					}
					assigned[anchor.Key]++
					groups = append(groups, g)
				}
				cluster = nil
			}

			for _, r := range rgRes {
				if len(cluster) > 0 {
					prev := cluster[len(cluster)-1]
					creatorMatch := r.CreatedBy == "" || prev.CreatedBy == "" || strings.EqualFold(r.CreatedBy, prev.CreatedBy)
					if r.Created.Sub(prev.Created) > window || !creatorMatch {
						flushCluster()
					}
				}
				cluster = append(cluster, r)
			}
			flushCluster()
		}
	}

	// timestamp proximity fallback
	var ungrouped []*Resource
	for _, r := range rs {
		if assigned[r.Key] > 0 {
			continue
		}
		if g, why, hyp := nearest(groups, r, window); g != nil {
			g.Members = append(g.Members, Member{R: r, Why: why, Hypothesis: hyp, Kind: "hyp"})
		} else {
			ungrouped = append(ungrouped, r)
		}
	}
	return groups, ungrouped
}

func nearest(groups []*Group, r *Resource, window time.Duration) (*Group, string, string) {
	if window <= 0 || r.Created.IsZero() {
		return nil, "", ""
	}
	best := window + 1
	var bestG *Group
	var why, hyp string
	for _, g := range groups {
		cands := []*Resource{g.Anchor}
		for _, m := range g.Members {
			if m.Hypothesis == "" {
				cands = append(cands, m.R)
			}
		}
		for _, c := range cands {
			if r.RG != "" && c.RG != "" && !strings.EqualFold(r.RG, c.RG) {
				continue
			}
			if r.CreatedBy != "" && c.CreatedBy != "" && !strings.EqualFold(r.CreatedBy, c.CreatedBy) {
				continue
			}
			for _, ev := range []struct {
				t     time.Time
				label string
			}{
				{c.Created, "was created"},
				{c.Changed, "was last changed"},
			} {
				if ev.t.IsZero() || (c.TimeApprox && ev.label == "was created") {
					continue
				}
				d := r.Created.Sub(ev.t)
				ad := d
				if ad < 0 {
					ad = -ad
				}
				if ad >= best {
					continue
				}
				best, bestG = ad, g
				dir := "after"
				if d < 0 {
					dir = "before"
				}
				why = fmt.Sprintf("created %s %s %s %s (same RG)", fmtDur(ad), dir, c.Name, ev.label)
				hyp = fmt.Sprintf("time proximity %s", fmtDur(ad))
			}
		}
	}
	return bestG, why, hyp
}

func countShared(groups []*Group) map[string]int {
	m := map[string]int{}
	for _, g := range groups {
		for _, mem := range g.Members {
			m[mem.R.Key]++
		}
	}
	return m
}

// Managed identity helpers

func propStr(props interface{}, key string) string {
	m, ok := props.(map[string]interface{})
	if !ok {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func lastSeg(id string) string {
	id = strings.TrimRight(id, "/")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

func collectBundleIdentities(g *Group, resByKey map[string]*Resource) []ManagedIDRef {
	var out []ManagedIDRef
	seen := map[string]bool{}

	add := func(ref ManagedIDRef) {
		key := ref.Kind + "|" + strings.ToLower(ref.PrincipalID) + "|" + strings.ToLower(ref.ResourceID) + "|" + strings.ToLower(ref.Label)
		if ref.PrincipalID != "" {
			key = ref.Kind + "|" + strings.ToLower(ref.PrincipalID)
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ref)
	}

	inspect := func(r *Resource) {
		if r == nil {
			return
		}
		if r.Identity != nil {
			if r.Identity.PrincipalID != "" {
				add(ManagedIDRef{
					Kind:        "system-assigned",
					PrincipalID: r.Identity.PrincipalID,
					Label:       r.Name,
					ResourceID:  r.Key,
				})
			}
			if len(r.Identity.UserAssignedIdentities) > 0 {
				keys := make([]string, 0, len(r.Identity.UserAssignedIdentities))
				for k := range r.Identity.UserAssignedIdentities {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, uID := range keys {
					uVal := r.Identity.UserAssignedIdentities[uID]
					uKey := strings.ToLower(strings.TrimRight(uID, "/"))
					pid := uVal.PrincipalID
					label := lastSeg(uID)
					if uRes := resByKey[uKey]; uRes != nil {
						label = uRes.Name
						if pid == "" {
							pid = propStr(uRes.Props, "principalId")
						}
					}
					add(ManagedIDRef{
						Kind:        "user-assigned",
						PrincipalID: pid,
						Label:       label,
						UsedBy:      r.Name,
						ResourceID:  uKey,
					})
				}
			}
		}
		if strings.EqualFold(r.Type, "microsoft.managedidentity/userassignedidentities") {
			add(ManagedIDRef{
				Kind:        "user-assigned",
				PrincipalID: propStr(r.Props, "principalId"),
				Label:       r.Name,
				ResourceID:  r.Key,
			})
		}
	}

	inspect(g.Anchor)
	for _, m := range g.Members {
		inspect(m.R)
	}
	return out
}

// RBAC & Permission Logic

func hasAuthDenied(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "authorizationfailed") ||
		strings.Contains(s, "does not have authorization") ||
		strings.Contains(s, "roleassignments/read") ||
		strings.Contains(s, "permissions/read") ||
		strings.Contains(s, "status code 403")
}

func hasGraphDenied(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "insufficient privileges") ||
		strings.Contains(s, "authorization_requestdenied") ||
		strings.Contains(s, "microsoft graph") ||
		strings.Contains(s, "graph.microsoft.com") ||
		strings.Contains(s, "does not exist in the directory")
}

func roleDisplayName(ra RoleAssignment) string {
	if ra.RoleDefinitionName != "" {
		return ra.RoleDefinitionName
	}
	if ra.RoleDefinitionID != "" {
		return lastSeg(ra.RoleDefinitionID)
	}
	return "unknown"
}

func scopeRank(scope string) int {
	ls := strings.ToLower(strings.TrimRight(scope, "/"))
	switch {
	case ls == "":
		return 0
	case strings.Contains(ls, "/managementgroups/"):
		return 1
	case !strings.Contains(ls, "/resourcegroups/"):
		return 2
	case !strings.Contains(ls, "/providers/"):
		return 3
	default:
		return 4
	}
}

func shortScope(scope, subID string) string {
	s := strings.TrimRight(scope, "/")
	ls := strings.ToLower(s)
	if ls == "" || ls == "/" {
		return "root (/)"
	}
	if i := strings.Index(ls, "/managementgroups/"); i >= 0 {
		return "mg: " + strings.Trim(s[i+len("/managementgroups/"):], "/")
	}
	if ls == "/subscriptions/"+strings.ToLower(subID) {
		return "sub"
	}
	if strings.HasPrefix(ls, "/subscriptions/") {
		rest := s[len("/subscriptions/"):]
		parts := strings.FieldsFunc(rest, func(r rune) bool { return r == '/' })
		if len(parts) == 1 {
			return "sub:" + shortID(parts[0])
		}
		if len(parts) == 3 && strings.EqualFold(parts[1], "resourceGroups") {
			return "rg: " + parts[2]
		}
		if len(parts) >= 7 && strings.EqualFold(parts[1], "resourceGroups") {
			if len(parts) >= 9 {
				last := parts[len(parts)-1]
				if strings.EqualFold(last, "default") {
					last = parts[len(parts)-2]
				}
				return fmt.Sprintf("rg: %s/%s/%s", parts[2], parts[6], last)
			}
			return fmt.Sprintf("rg: %s/%s", parts[2], parts[6])
		}
	}
	return s
}

func sortRoleAssignments(ras []RoleAssignment) {
	sort.SliceStable(ras, func(i, j int) bool {
		ri, rj := scopeRank(ras[i].Scope), scopeRank(ras[j].Scope)
		if ri != rj {
			return ri < rj
		}
		ni, nj := strings.ToLower(roleDisplayName(ras[i])), strings.ToLower(roleDisplayName(ras[j]))
		if ni != nj {
			return ni < nj
		}
		return strings.ToLower(ras[i].Scope) < strings.ToLower(ras[j].Scope)
	})
}

func indexByPrincipal(ras []RoleAssignment) map[string][]RoleAssignment {
	m := map[string][]RoleAssignment{}
	for _, ra := range ras {
		if ra.PrincipalID != "" {
			k := strings.ToLower(ra.PrincipalID)
			m[k] = append(m[k], ra)
		}
	}
	for k := range m {
		sortRoleAssignments(m[k])
	}
	return m
}

func roleColorCode(roleName string) string {
	ln := strings.ToLower(roleName)
	switch {
	case ln == "owner" || ln == "user access administrator" || ln == "role based access control administrator":
		return "1;33" // bright yellow
	case strings.Contains(ln, "contributor") || strings.Contains(ln, "administrator") || strings.Contains(ln, "admin"):
		return "33" // yellow
	case strings.Contains(ln, "reader"):
		return "32" // green
	default:
		return "94" // bright blue
	}
}

func formatRoleList(p palette, ras []RoleAssignment, subID string) string {
	if len(ras) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	for _, ra := range ras {
		rn := roleDisplayName(ra)
		sc := shortScope(ra.Scope, subID)
		key := strings.ToLower(rn + "|" + sc)
		if seen[key] {
			continue
		}
		seen[key] = true
		parts = append(parts, p.c(roleColorCode(rn), rn)+" "+p.c("2", "("+sc+")"))
	}
	if len(parts) > 4 {
		extra := len(parts) - 4
		parts = append(parts[:4], p.c("2", fmt.Sprintf("+%d more", extra)))
	}
	return strings.Join(parts, ", ")
}

// wildcard matching for Azure RBAC action strings (case-insensitive)
func matchWildcard(pattern, target string) bool {
	p, s := strings.ToLower(pattern), strings.ToLower(target)
	pi, si, starIdx, matchIdx := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			starIdx, matchIdx = pi, si
			pi++
		case starIdx != -1:
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func actionAllowed(blocks []PermissionBlock, target string, dataPlane bool) bool {
	for _, b := range blocks {
		allowList, denyList := b.Actions, b.NotActions
		if dataPlane {
			allowList, denyList = b.DataActions, b.NotDataActions
		}
		allowed := false
		for _, a := range allowList {
			if matchWildcard(a, target) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		denied := false
		for _, na := range denyList {
			if matchWildcard(na, target) {
				denied = true
				break
			}
		}
		if !denied {
			return true
		}
	}
	return false
}

func hasAnyDataAction(blocks []PermissionBlock) bool {
	for _, b := range blocks {
		if len(b.DataActions) > 0 {
			return true
		}
	}
	return false
}

// formatting helpers

type palette struct{ on bool }

func (p palette) c(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func useColor(disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func padRight(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

func padVisRight(s string, n int) string {
	if w := visWidth(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

func trunc(s string, max int) string {
	rs := []rune(s)
	if len(rs) <= max || max < 4 {
		return s
	}
	return string(rs[:max-1]) + "…"
}

func shortID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 13 {
		return id
	}
	return id[:6] + "…" + id[len(id)-4:]
}

func shortType(t string) string {
	if len(t) > 10 && strings.EqualFold(t[:10], "microsoft.") {
		return t[10:]
	}
	return t
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func fmtSpan(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	if d >= time.Hour {
		d = d.Round(time.Minute)
	} else {
		d = d.Round(time.Second)
	}
	const day = 24 * time.Hour
	days := int64(d / day)
	d -= time.Duration(days) * day
	hours := int64(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int64(d / time.Minute)
	d -= time.Duration(mins) * time.Minute
	secs := int64(d / time.Second)

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if mins > 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	out := strings.Join(parts, "")
	if neg {
		return "-" + out
	}
	return out
}

func fmtDur(d time.Duration) string {
	if d > -time.Minute && d < time.Minute {
		return d.Round(100 * time.Millisecond).String()
	}
	return fmtSpan(d)
}

func offset(t, base time.Time) string {
	if t.IsZero() || base.IsZero() {
		return ""
	}
	d := t.Sub(base)
	if d >= 0 {
		return "+" + fmtSpan(d)
	}
	return fmtSpan(d)
}

func before(a, b time.Time) bool {
	if a.IsZero() {
		return false
	}
	if b.IsZero() {
		return true
	}
	return a.Before(b)
}

func newer(a, b time.Time) bool {
	if a.IsZero() {
		return false
	}
	if b.IsZero() {
		return true
	}
	return a.After(b)
}

func looksAzureDefault(r *Resource) bool {
	rg := strings.ToLower(r.RG)
	return strings.EqualFold(r.Type, "Microsoft.Network/networkWatchers") ||
		rg == "networkwatcherrg" || strings.HasPrefix(rg, "defaultresourcegroup-")
}

func termCols() int {
	if cols, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && cols >= 60 {
		return cols
	}
	return 0
}

func tableMaxWidth() int {
	if cols := termCols(); cols > 0 {
		if cols > 140 {
			return 140
		}
		return cols - 2
	}
	return 116
}

func wrapText(s string, width int) []string {
	if s == "" || width <= 0 {
		return []string{s}
	}
	rs := []rune(s)
	if len(rs) <= width {
		return []string{s}
	}
	var lines []string
	for len(rs) > width {
		split, dropSpace := -1, false
		for i := width; i > 0; i-- {
			if rs[i] == ' ' {
				split, dropSpace = i, true
				break
			}
			if rs[i-1] == '/' {
				split = i
				break
			}
		}
		if split > 0 {
			lines = append(lines, string(rs[:split]))
			if dropSpace {
				rs = rs[split+1:]
				for len(rs) > 0 && rs[0] == ' ' {
					rs = rs[1:]
				}
			} else {
				rs = rs[split:]
			}
		} else {
			lines = append(lines, string(rs[:width]))
			rs = rs[width:]
		}
	}
	if len(rs) > 0 {
		lines = append(lines, string(rs))
	}
	return lines
}

type tableCell struct {
	text  string
	color string
}

type tableColumn struct {
	title    string
	minWidth int
}

func renderTable(w io.Writer, p palette, indent string, cols []tableColumn, groups [][][]tableCell, maxTableWidth int) {
	if len(cols) == 0 {
		return
	}
	widths := make([]int, len(cols))
	for c, col := range cols {
		widths[c] = max(len([]rune(col.title)), col.minWidth)
	}
	for _, grp := range groups {
		for _, row := range grp {
			for c := 0; c < len(cols) && c < len(row); c++ {
				if l := len([]rune(row[c].text)); l > widths[c] {
					widths[c] = l
				}
			}
		}
	}

	overhead := len([]rune(indent)) + 1 + len(cols)*3
	if avail := maxTableWidth - overhead; avail > 0 {
		sum := 0
		for _, cw := range widths {
			sum += cw
		}
		for sum > avail {
			best, bestSlack := -1, 0
			for c, col := range cols {
				minW := max(col.minWidth, len([]rune(col.title)))
				if slack := widths[c] - minW; slack > bestSlack {
					bestSlack, best = slack, c
				}
			}
			if best < 0 {
				break
			}
			widths[best]--
			sum--
		}
	}

	drawRule := func(left, mid, right string) {
		var b strings.Builder
		b.WriteString(indent)
		b.WriteString(left)
		for c, cw := range widths {
			b.WriteString(strings.Repeat("─", cw+2))
			if c < len(widths)-1 {
				b.WriteString(mid)
			}
		}
		b.WriteString(right)
		fmt.Fprintln(w, p.c("2", b.String()))
	}

	drawRule("┌", "┬", "┐")
	fmt.Fprintf(w, "%s%s", indent, p.c("2", "│"))
	for c, col := range cols {
		fmt.Fprintf(w, " %s %s", p.c("1", padRight(col.title, widths[c])), p.c("2", "│"))
	}
	fmt.Fprintln(w)
	drawRule("├", "┼", "┤")

	for gi, grp := range groups {
		if gi > 0 {
			drawRule("├", "┼", "┤")
		}
		for _, row := range grp {
			wrapped := make([][]string, len(cols))
			maxLines := 1
			for c := range cols {
				var cell tableCell
				if c < len(row) {
					cell = row[c]
				}
				wrapped[c] = wrapText(cell.text, widths[c])
				if len(wrapped[c]) > maxLines {
					maxLines = len(wrapped[c])
				}
			}
			for li := 0; li < maxLines; li++ {
				fmt.Fprintf(w, "%s%s", indent, p.c("2", "│"))
				for c := range cols {
					txt := ""
					if li < len(wrapped[c]) {
						txt = wrapped[c][li]
					}
					cellOut := padRight(txt, widths[c])
					if txt != "" && c < len(row) && row[c].color != "" {
						cellOut = padVisRight(p.c(row[c].color, txt), widths[c])
					}
					fmt.Fprintf(w, " %s %s", cellOut, p.c("2", "│"))
				}
				fmt.Fprintln(w)
			}
		}
	}
	drawRule("└", "┴", "┘")
}

type roleScopeRow struct {
	role  string
	scope string
	color string
}

type miTableEntry struct {
	bundleNum int
	mi        ManagedIDRef
}

func resolveMIRoles(rbac *RBACData, mi ManagedIDRef, subID string) (rows []roleScopeRow, statusMsg, statusColor string) {
	switch {
	case rbac == nil || rbac.AllRolesStatus == "unavailable":
		return nil, "roles unavailable", "2"
	case rbac.AllRolesStatus == "denied":
		return nil, "unknown (Reader required)", "33"
	case rbac.AllRolesStatus == "error":
		return nil, "roles lookup failed", "33"
	case mi.PrincipalID == "":
		return nil, "principalId not present", "2"
	}
	ras := rbac.ByPrincipal[strings.ToLower(mi.PrincipalID)]
	if len(ras) == 0 {
		return nil, "no sub roles", "2"
	}
	seen := map[string]bool{}
	for _, ra := range ras {
		rn := roleDisplayName(ra)
		sc := shortScope(ra.Scope, subID)
		rt := rn
		if ra.Condition != "" {
			rt += " [ABAC]"
		}
		k := strings.ToLower(rt + "|" + sc)
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, roleScopeRow{role: rt, scope: sc, color: roleColorCode(rn)})
	}
	return rows, "", ""
}

// session & view

type scanOpts struct {
	window          time.Duration
	depth           int
	subWindow       time.Duration
	deep            bool
	deployments     bool
	rbac            bool
	since           time.Time
	hasSince        bool
	noState         bool
	listFile        string
	graphFile       string
	deploymentsFile string
	rbacFile        string
	snapshotFile    string
}

type SubSession struct {
	Sub       Subscription
	Resources []*Resource
	Index     *Index
	Groups    []*Group
	Ungrouped []*Resource
	Shared    map[string]int
	BundleNo  map[string]int
	RBAC      *RBACData
	Since     time.Time
	ScannedAt time.Time
}

type view struct {
	w         io.Writer
	p         palette
	online    bool
	subs      []Subscription
	active    *SubSession
	cache     map[string]*SubSession
	oid       string
	opts      scanOpts
	filter    string
	subWindow time.Duration
}

func (v *view) isNew(r *Resource) bool {
	return v.active != nil && !v.active.Since.IsZero() && r.Created.After(v.active.Since)
}

func (v *view) tag(r *Resource) string {
	if v.isNew(r) {
		return " " + v.p.c("1;32", "● new")
	}
	return ""
}

func (v *view) groupTag(g *Group) string {
	if v.isNew(g.Anchor) {
		return " " + v.p.c("1;32", "● new")
	}
	for _, m := range g.Members {
		if v.isNew(m.R) {
			return " " + v.p.c("1;32", "● new inside")
		}
	}
	return ""
}

func (v *view) matchesFilter(g *Group, q string) bool {
	if q == "" {
		return true
	}
	lq := strings.ToLower(strings.TrimSpace(q))
	switch lq {
	case "new":
		return v.groupTag(g) != ""
	case "mi", "identity":
		return len(collectBundleIdentities(g, v.active.Index.Res)) > 0
	}
	if strings.HasPrefix(lq, "rg:") {
		rg := strings.TrimSpace(lq[3:])
		if strings.Contains(strings.ToLower(g.Anchor.RG), rg) {
			return true
		}
		for _, m := range g.Members {
			if strings.Contains(strings.ToLower(m.R.RG), rg) {
				return true
			}
		}
		return false
	}
	hit := func(r *Resource) bool {
		return strings.Contains(strings.ToLower(r.Name), lq) ||
			strings.Contains(strings.ToLower(r.Type), lq) ||
			strings.Contains(strings.ToLower(r.RG), lq) ||
			strings.Contains(strings.ToLower(r.CreatedBy), lq)
	}
	if hit(g.Anchor) {
		return true
	}
	for _, m := range g.Members {
		if hit(m.R) {
			return true
		}
	}
	return false
}

func (v *view) filteredGroups() []*Group {
	if v.active == nil || v.filter == "" {
		if v.active == nil {
			return nil
		}
		return v.active.Groups
	}
	var out []*Group
	for _, g := range v.active.Groups {
		if v.matchesFilter(g, v.filter) {
			out = append(out, g)
		}
	}
	return out
}

func (v *view) status() {
	s := v.active
	if s == nil {
		return
	}
	delimW := 80
	if cols := termCols(); cols > 0 {
		delimW = min(cols, 114)
	}
	fmt.Fprintf(v.w, "\n%s\n", v.p.c("2", strings.Repeat("─", delimW)))

	modeBadge := v.p.c("1;32", "● online")
	if !v.online {
		modeBadge = v.p.c("1;33", "● offline")
	}
	subLabel := s.Sub.Name
	if subLabel == "" {
		subLabel = s.Sub.ID
	} else if s.Sub.ID != "" && s.Sub.ID != "offline" {
		subLabel += " (" + shortID(s.Sub.ID) + ")"
	}
	subCount := ""
	if v.online && len(v.subs) > 1 {
		subCount = v.p.c("94", fmt.Sprintf(" [%d subs]", len(v.subs)))
	}
	userText := ""
	if s.Sub.User.Name != "" {
		userText = " · " + v.p.c("2", "user: ") + s.Sub.User.Name
	}
	fmt.Fprintf(v.w, "%s  %s %s%s%s\n", modeBadge, v.p.c("2", "sub:"), v.p.c("1", subLabel), subCount, userText)

	if s.RBAC != nil {
		var rbacLine string
		switch s.RBAC.UserRolesStatus {
		case "ok":
			if len(s.RBAC.UserRoles) == 0 {
				rbacLine = v.p.c("2", "no role assignments found in this subscription")
			} else {
				rbacLine = formatRoleList(v.p, s.RBAC.UserRoles, s.Sub.ID)
			}
		case "denied":
			rbacLine = v.p.c("33", "unknown") + v.p.c("2", " (Reader role / roleAssignments/read required)")
			if s.RBAC.Effective.Status == "ok" {
				rbacLine += v.p.c("32", " · effective perms ready ('r')")
			}
		case "unavailable":
			if !v.online {
				rbacLine = v.p.c("2", "not captured in offline input (use -save or -rbacf)")
			} else {
				rbacLine = v.p.c("2", "skipped (-rbac=false)")
			}
		default:
			rbacLine = v.p.c("33", "unknown")
			if s.RBAC.UserRolesErr != "" {
				rbacLine += " " + v.p.c("2", "("+trunc(s.RBAC.UserRolesErr, 54)+")")
			}
		}
		fmt.Fprintf(v.w, "          %s %s\n", v.p.c("2", "rbac:"), rbacLine)
	}
	if !s.Since.IsZero() {
		fmt.Fprintf(v.w, "          %s %s UTC\n", v.p.c("2", "new after:"), fmtTime(s.Since))
	}
	if v.filter != "" {
		vis := v.filteredGroups()
		fmt.Fprintf(v.w, "          %s %s (%d of %d bundles · type %s to clear filter)\n",
			v.p.c("2", "filter:"), v.p.c("1;34", v.filter), len(vis), len(s.Groups), v.p.c("1;33", "'/'"))
	}
}

func (v *view) list() {
	s := v.active
	groups := v.filteredGroups()

	title := "Bundles of related resources (newest first, all times UTC)"
	if v.filter != "" {
		title = fmt.Sprintf("Bundles matching %s (%d of %d, newest first, all times UTC · %s to clear)",
			v.p.c("1;34", fmt.Sprintf("%q", v.filter)), len(groups), len(s.Groups), v.p.c("1;33", "'/'"))
	}
	fmt.Fprintf(v.w, "\n%s\n", v.p.c("1", title))
	if len(groups) > 0 {
		fmt.Fprintf(v.w, "      %s\n", v.p.c("2", padRight("BUNDLE", 27)+padRight("ANCHOR TYPE", 35)+padRight("CONTENTS", 27)+"ANCHOR CREATED"))
	} else {
		if v.filter != "" {
			fmt.Fprintf(v.w, "  (no bundles match filter %q · type %s to clear filter)\n", v.filter, v.p.c("1;33", "'/'"))
		} else {
			fmt.Fprintln(v.w, "  (no bundles or anchor resources found)")
		}
	}

	for _, g := range groups {
		num := s.BundleNo[g.Anchor.Key]
		hypCount := 0
		for _, m := range g.Members {
			if m.Hypothesis != "" {
				hypCount++
			}
		}
		count := fmt.Sprintf("%d resources", len(g.Members)+1)
		if hypCount > 0 {
			count += fmt.Sprintf(" (%d hyp)", hypCount)
		}
		miTag := ""
		if mis := collectBundleIdentities(g, s.Index.Res); len(mis) > 0 {
			miTag = " " + v.p.c("94", fmt.Sprintf("[MI:%d]", len(mis)))
		}
		fmt.Fprintf(v.w, " [%2d] %s %s %s %s%s%s\n", num,
			padRight(trunc(g.Anchor.Name, 26), 26),
			padRight(trunc(shortType(g.Anchor.Type), 34), 34),
			padRight(count, 26),
			v.p.c("2", fmtTime(g.Anchor.Created)),
			miTag,
			v.groupTag(g))
	}
	if len(s.Ungrouped) > 0 && v.filter == "" {
		fmt.Fprintf(v.w, " [ u] ungrouped (%d resources that matched nothing)\n", len(s.Ungrouped))
	}
}

type section struct {
	title   string
	kind    string
	members []Member
}

func kindRank(k string) int {
	switch k {
	case "deploy":
		return 0
	case "child":
		return 1
	case "managed":
		return 2
	case "ref":
		return 3
	case "batch":
		return 4
	case "hyp":
		return 5
	}
	return 6
}

func tailType(t string, n int) string {
	parts := strings.Split(shortType(t), "/")
	if len(parts) > n {
		parts = parts[len(parts)-n:]
	}
	return strings.Join(parts, "/")
}

func buildSections(g *Group) []section {
	a := g.Anchor
	idx := map[string]int{}
	var secs []section
	for _, m := range g.Members {
		key, title := m.Kind, "other"
		switch m.Kind {
		case "child":
			t := tailType(m.R.Type, 2)
			key, title = "child|"+m.Via+"|"+t, t
			if m.Via != a.Name {
				title += " (under " + m.Via + ")"
			}
		case "managed":
			key, title = "managed|"+m.Via, "managed by "+m.Via
		case "deploy":
			key, title = "deploy|"+m.Via, "deployed together by template "+m.Via
		case "ref":
			title = "dependencies (referenced in properties)"
		case "batch":
			title = "created together (hypothesis: temporal cluster)"
		case "hyp":
			title = "probable matches (hypothesis: time proximity)"
		}
		i, ok := idx[key]
		if !ok {
			i = len(secs)
			idx[key] = i
			secs = append(secs, section{title: title, kind: m.Kind})
		}
		secs[i].members = append(secs[i].members, m)
	}
	sort.SliceStable(secs, func(i, j int) bool { return kindRank(secs[i].kind) < kindRank(secs[j].kind) })
	return secs
}

func (v *view) note(a *Resource, kind string, m Member) string {
	switch kind {
	case "ref":
		why := strings.TrimPrefix(m.Why, "referenced by "+a.Name+" ")
		return "↳ " + v.p.c("2", why)
	case "hyp":
		return "↳ " + v.p.c("2", m.Why) + " " + v.p.c("1;35", fmt.Sprintf("[hypothesis: %s]", m.Hypothesis))
	}
	return ""
}

type clusterMark struct {
	pos   int
	label string
}

func findClusters(ms []Member, window time.Duration) []clusterMark {
	marks := make([]clusterMark, len(ms))
	if window <= 0 {
		return marks
	}
	start := 0
	flush := func(end int) {
		n := end - start
		if n < 2 {
			return
		}
		span := ms[end-1].R.Created.Sub(ms[start].R.Created)
		approx := true
		for _, m := range ms[start:end] {
			if !m.R.TimeApprox {
				approx = false
			}
		}
		verb := "created"
		if approx {
			verb = "modified"
		}
		when := "in the same second"
		if span >= time.Second {
			when = "within " + fmtSpan(span)
		}
		for i := start; i < end; i++ {
			marks[i].pos = 2
		}
		marks[start].pos = 1
		marks[end-1].pos = 3
		marks[start+(n-1)/2].label = fmt.Sprintf("probably %s together · %d %s", verb, n, when)
	}
	for i := 1; i <= len(ms); i++ {
		if i == len(ms) || ms[i].R.Created.IsZero() || ms[i-1].R.Created.IsZero() ||
			ms[i].R.Created.Sub(ms[i-1].R.Created) > window {
			flush(i)
			start = i
		}
	}
	return marks
}

func visWidth(s string) int {
	n := 0
	esc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}

func (v *view) bracket(m clusterMark, gap int) string {
	if m.pos == 0 {
		return ""
	}
	gap += 2
	var edge string
	switch m.pos {
	case 1:
		edge = " " + strings.Repeat("─", gap-1) + "┐"
	case 2:
		edge = strings.Repeat(" ", gap) + "│"
	default:
		edge = " " + strings.Repeat("─", gap-1) + "┘"
	}
	out := v.p.c("35", edge)
	if m.label != "" {
		out += " " + v.p.c("1;35", m.label)
	}
	return out
}

func (v *view) elsewhereTag(m Member) string {
	if m.Root == nil {
		return "[in another bundle]"
	}
	name := m.Root.Name + " (" + tailType(m.Root.Type, 1) + ")"
	if n, ok := v.active.BundleNo[m.Root.Key]; ok {
		return fmt.Sprintf("[→ bundle #%d %s]", n, name)
	}
	return "[→ bundle " + name + "]"
}

func (v *view) renderIdentityLines(mis []ManagedIDRef, cont string) {
	rbac := v.active.RBAC
	for i, mi := range mis {
		leaf, sub := "├─", "│"
		if i == len(mis)-1 {
			leaf, sub = "└─", " "
		}
		badge := v.p.c("1;32", "[system-assigned]")
		if mi.Kind == "user-assigned" {
			badge = v.p.c("1;34", "[user-assigned]")
		}
		usedBy := ""
		if mi.UsedBy != "" && mi.UsedBy != mi.Label {
			usedBy = " " + v.p.c("2", "(used by "+mi.UsedBy+")")
		}
		pidText := ""
		if mi.PrincipalID != "" {
			pidText = " " + v.p.c("2", "oid: "+shortID(mi.PrincipalID))
		}
		fmt.Fprintf(v.w, "   %s  %s %s %s%s%s\n", cont, leaf, padRight(mi.Label, 24), badge, usedBy, pidText)

		rows, statusMsg, statusColor := resolveMIRoles(rbac, mi, v.active.Sub.ID)
		if len(rows) == 0 {
			switch statusMsg {
			case "no sub roles":
				statusMsg = "no RBAC role assignments in this subscription"
			case "unknown (Reader required)":
				statusMsg = "unknown (Reader role / roleAssignments/read required)"
			}
			fmt.Fprintf(v.w, "   %s  %s    ↳ %s %s\n", cont, sub, v.p.c("2", "roles:"), v.p.c(statusColor, statusMsg))
			continue
		}

		maxRoleW := 0
		for _, r := range rows {
			if l := len([]rune(r.role)); l > maxRoleW {
				maxRoleW = l
			}
		}
		for _, r := range rows {
			fmt.Fprintf(v.w, "   %s  %s    ↳ %s  %s\n",
				cont, sub,
				padVisRight(v.p.c(r.color, r.role), maxRoleW),
				v.p.c("2", "("+r.scope+")"))
		}
	}
}

func (v *view) renderMITable(indent string, includeBundle, includeOID bool, entries []miTableEntry) {
	if len(entries) == 0 {
		return
	}
	s := v.active
	var cols []tableColumn
	if includeBundle {
		cols = append(cols, tableColumn{title: "BUNDLE", minWidth: 6})
	}
	cols = append(cols,
		tableColumn{title: "IDENTITY", minWidth: 12},
		tableColumn{title: "TYPE", minWidth: 4},
		tableColumn{title: "ROLE", minWidth: 20},
		tableColumn{title: "SCOPE", minWidth: 16},
	)

	var groups [][][]tableCell
	for _, e := range entries {
		idLines := []tableCell{{text: e.mi.Label}}
		if includeOID && e.mi.PrincipalID != "" {
			idLines = append(idLines, tableCell{text: "oid: " + shortID(e.mi.PrincipalID), color: "2"})
		}
		if e.mi.UsedBy != "" && !strings.EqualFold(e.mi.UsedBy, e.mi.Label) {
			idLines = append(idLines, tableCell{text: "on: " + e.mi.UsedBy, color: "2"})
		}

		typeCell := tableCell{text: "sys", color: "32"}
		if e.mi.Kind == "user-assigned" {
			typeCell = tableCell{text: "uai", color: "94"}
		}

		rows, statusMsg, statusColor := resolveMIRoles(s.RBAC, e.mi, s.Sub.ID)
		var roleCells, scopeCells []tableCell
		if len(rows) == 0 {
			roleCells = []tableCell{{text: statusMsg, color: statusColor}}
			scopeCells = []tableCell{{text: "—", color: "2"}}
		} else {
			for _, r := range rows {
				roleCells = append(roleCells, tableCell{text: r.role, color: r.color})
				scopeCells = append(scopeCells, tableCell{text: r.scope})
			}
		}

		n := max(len(roleCells), len(idLines))
		grp := make([][]tableCell, 0, n)
		for i := 0; i < n; i++ {
			var idC, rC, sC, tC tableCell
			if i < len(idLines) {
				idC = idLines[i]
			}
			if i == 0 {
				tC = typeCell
			}
			if i < len(roleCells) {
				rC, sC = roleCells[i], scopeCells[i]
			}
			if includeBundle {
				var bC tableCell
				if i == 0 {
					bC = tableCell{text: fmt.Sprintf("#%d", e.bundleNum)}
				}
				grp = append(grp, []tableCell{bC, idC, tC, rC, sC})
			} else {
				grp = append(grp, []tableCell{idC, tC, rC, sC})
			}
		}
		groups = append(groups, grp)
	}

	renderTable(v.w, v.p, indent, cols, groups, tableMaxWidth())
}

func (v *view) group(g *Group) {
	s := v.active
	a := g.Anchor
	loc := ""
	if a.Location != "" && a.Location != "deployment" {
		loc = " · " + a.Location
	}
	num := ""
	if n, ok := s.BundleNo[a.Key]; ok {
		num = fmt.Sprintf("#%d ", n)
	}
	fmt.Fprintf(v.w, "\n%s  %s  %s\n", v.p.c("1;36", "▸ "+num+a.Name), v.p.c("2", shortType(a.Type)), v.p.c("2", a.RG+loc))
	line := "created " + fmtTime(a.Created)
	if a.CreatedBy != "" {
		line += " by " + a.CreatedBy
	}
	if !a.Changed.IsZero() {
		line += " · changed " + fmtTime(a.Changed)
	}
	line += " (UTC)"
	fmt.Fprintf(v.w, "   %s%s\n", v.p.c("2", line), v.tag(a))

	secs := buildSections(g)
	mis := collectBundleIdentities(g, s.Index.Res)
	hasMIs := len(mis) > 0

	for si, sec := range secs {
		lastSec := si == len(secs)-1 && !hasMIs
		branch, cont := "├─", "│"
		if lastSec {
			branch, cont = "└─", " "
		}
		fmt.Fprintf(v.w, "   %s %s\n", branch, v.p.c("1", fmt.Sprintf("%s · %d", sec.title, len(sec.members))))

		ms := append([]Member(nil), sec.members...)
		sort.SliceStable(ms, func(i, j int) bool { return before(ms[i].R.Created, ms[j].R.Created) })

		lines := make([]string, len(ms))
		width := 0
		for i, m := range ms {
			r := m.R
			when := fmtTime(r.Created)
			if r.TimeApprox && !r.Created.IsZero() {
				when = "~" + when
			}
			if off := offset(r.Created, a.Created); off != "" {
				when += " (" + off + ")"
			}
			text := padRight(r.Name, 28) + " "
			if sec.kind != "child" {
				text += padRight(shortType(r.Type), 34) + " "
			}
			text += when
			if r.RG != a.RG && r.RG != "" {
				text += " " + v.p.c("2", "rg: "+r.RG)
			}
			if s.Shared[r.Key] > 1 {
				text += " " + v.p.c("35", "[shared]")
			}
			if m.Elsewhere {
				text += " " + v.p.c("36", v.elsewhereTag(m))
			}
			lines[i] = text + v.tag(r)
			if w := visWidth(lines[i]); w > width {
				width = w
			}
		}

		marks := make([]clusterMark, len(ms))
		if sec.kind == "child" {
			marks = findClusters(ms, v.subWindow)
		}
		for i, m := range ms {
			leaf, sub := "├─", "│"
			if i == len(ms)-1 {
				leaf, sub = "└─", " "
			}
			fmt.Fprintf(v.w, "   %s  %s %s%s\n", cont, leaf, lines[i], v.bracket(marks[i], width-visWidth(lines[i])))
			if note := v.note(a, sec.kind, m); note != "" {
				fmt.Fprintf(v.w, "   %s  %s    %s\n", cont, sub, note)
			}
		}
	}

	if hasMIs {
		fmt.Fprintf(v.w, "   └─ %s\n", v.p.c("1;34", fmt.Sprintf("managed identities · %d", len(mis))))
		v.renderIdentityLines(mis, " ")
	}
}

func (v *view) ungrouped(rs []*Resource) {
	fmt.Fprintf(v.w, "\n%s\n", v.p.c("1;33", fmt.Sprintf("▸ Ungrouped (%d)", len(rs))))
	sorted := append([]*Resource(nil), rs...)
	sort.SliceStable(sorted, func(i, j int) bool { return before(sorted[i].Created, sorted[j].Created) })
	for _, r := range sorted {
		hint := ""
		if looksAzureDefault(r) {
			hint = "  " + v.p.c("2", "(looks like an Azure-created default)")
		}
		fmt.Fprintf(v.w, "   • %s %s %s %s%s%s\n",
			padRight(r.Name, 28), padRight(shortType(r.Type), 34), fmtTime(r.Created),
			v.p.c("2", "rg: "+r.RG), v.tag(r), hint)
	}
}

func (v *view) dump(groups []*Group, ungrouped []*Resource, withStatus bool) {
	if withStatus {
		v.status()
	}
	for _, g := range groups {
		v.group(g)
	}
	if len(ungrouped) > 0 && v.filter == "" {
		v.ungrouped(ungrouped)
	}
}

// RBAC Views ('r', 'r perms', 'r <bundle#>')

func (v *view) renderRBACOverview() {
	s := v.active
	rbac := s.RBAC
	fmt.Fprintf(v.w, "\n%s  %s\n", v.p.c("1;36", "▸ RBAC & Identity Overview"), v.p.c("2", s.Sub.Name))
	if s.Sub.User.Name != "" {
		oid := ""
		if rbac != nil && rbac.CallerOID != "" {
			oid = " · oid " + shortID(rbac.CallerOID)
		}
		fmt.Fprintf(v.w, "   %s %s (%s%s)\n", v.p.c("2", "caller:"), s.Sub.User.Name, s.Sub.User.Type, oid)
	}

	if rbac == nil {
		fmt.Fprintln(v.w, "   (no RBAC information loaded)")
		return
	}

	fmt.Fprintf(v.w, "\n   %s\n", v.p.c("1", "Your role assignments"))
	switch rbac.UserRolesStatus {
	case "ok":
		if len(rbac.UserRoles) == 0 {
			fmt.Fprintln(v.w, "   • "+v.p.c("2", "no role assignments returned for this caller in "+s.Sub.Name))
		} else {
			maxRoleW := 18
			for _, ra := range rbac.UserRoles {
				if l := len([]rune(roleDisplayName(ra))); l > maxRoleW {
					maxRoleW = l
				}
			}
			for _, ra := range rbac.UserRoles {
				rn := roleDisplayName(ra)
				sc := shortScope(ra.Scope, s.Sub.ID)
				via := ""
				if ra.PrincipalType != "" && !strings.EqualFold(ra.PrincipalType, "user") && rbac.Caller.Type == "user" {
					via = " " + v.p.c("94", "[via "+strings.ToLower(ra.PrincipalType)+"]")
				} else if scopeRank(ra.Scope) < 2 {
					via = " " + v.p.c("2", "[inherited]")
				}
				cond := ""
				if ra.Condition != "" {
					cond = " " + v.p.c("35", "[ABAC condition]")
				}
				fmt.Fprintf(v.w, "   • %s  %s%s%s\n",
					padVisRight(v.p.c(roleColorCode(rn), rn), maxRoleW),
					v.p.c("2", "scope: "+sc), via, cond)
			}
		}
	case "denied":
		fmt.Fprintf(v.w, "   • %s %s\n",
			v.p.c("33", "unknown"),
			v.p.c("2", "(requires Microsoft.Authorization/roleAssignments/read, e.g. Reader role)"))
	case "unavailable":
		if !v.online {
			fmt.Fprintln(v.w, "   • "+v.p.c("2", "not captured in offline files (use -save or -rbacf)"))
		} else {
			fmt.Fprintln(v.w, "   • "+v.p.c("2", "skipped (-rbac=false)"))
		}
	default:
		fmt.Fprintf(v.w, "   • %s (%s)\n", v.p.c("33", "error"), rbac.UserRolesErr)
	}

	fmt.Fprintf(v.w, "\n   %s\n", v.p.c("1", "Effective subscription permissions"))
	switch rbac.Effective.Status {
	case "ok":
		fmt.Fprintf(v.w, "   • %s\n", summarizeCapabilities(rbac.Effective.Blocks, ""))
	case "denied":
		fmt.Fprintln(v.w, "   • "+v.p.c("33", "denied")+" "+v.p.c("2", "(requires Microsoft.Authorization/permissions/read)"))
	default:
		fmt.Fprintln(v.w, "   • "+v.p.c("2", "unavailable"))
	}

	var miEntries []miTableEntry
	for _, g := range s.Groups {
		mis := collectBundleIdentities(g, s.Index.Res)
		if len(mis) == 0 {
			continue
		}
		num := s.BundleNo[g.Anchor.Key]
		for _, mi := range mis {
			miEntries = append(miEntries, miTableEntry{bundleNum: num, mi: mi})
		}
	}
	if len(miEntries) > 0 {
		fmt.Fprintf(v.w, "\n   %s\n", v.p.c("1", fmt.Sprintf("Managed identities across bundles (%d)", len(miEntries))))
		v.renderMITable("   ", true, false, miEntries)
	}

	fmt.Fprintf(v.w, "\n   %s\n", v.p.c("2", "tip: 'r perms' for role actions · 'r perms full' for full list · 'r <bundle#>' for bundle access"))
}

func summarizeCapabilities(blocks []PermissionBlock, resourceType string) string {
	readOp := "Microsoft.Resources/subscriptions/resourceGroups/read"
	writeOp := "Microsoft.Resources/deployments/write"
	delOp := "Microsoft.Resources/deployments/delete"
	if resourceType != "" && !strings.EqualFold(resourceType, "Deployment/Batch") {
		readOp = resourceType + "/read"
		writeOp = resourceType + "/write"
		delOp = resourceType + "/delete"
	}
	pill := func(ok bool, label string) string {
		if ok {
			return "[✓ " + label + "]"
		}
		return "[✗ " + label + "]"
	}
	return strings.Join([]string{
		pill(actionAllowed(blocks, readOp, false), "read"),
		pill(actionAllowed(blocks, writeOp, false), "write"),
		pill(actionAllowed(blocks, delOp, false), "delete"),
		pill(actionAllowed(blocks, "Microsoft.Authorization/roleAssignments/write", false), "assign RBAC"),
		pill(hasAnyDataAction(blocks), "data-plane"),
	}, " ")
}

func (v *view) renderPermList(label, color string, items []string, full bool) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(v.w, "     %s (%d)\n", v.p.c(color, label), len(items))
	limit := len(items)
	if !full && limit > 18 {
		limit = 18
	}
	for i := 0; i < limit; i++ {
		fmt.Fprintf(v.w, "       • %s\n", items[i])
	}
	if limit < len(items) {
		fmt.Fprintf(v.w, "       %s\n", v.p.c("2", fmt.Sprintf("… +%d more (run 'r perms full' to display all)", len(items)-limit)))
	}
}

func (v *view) renderPermissionBlocks(blocks []PermissionBlock, full bool) {
	for idx, b := range blocks {
		if len(blocks) > 1 {
			fmt.Fprintf(v.w, "   %s\n", v.p.c("2", fmt.Sprintf("block #%d:", idx+1)))
		}
		v.renderPermList("Actions", "32", b.Actions, full)
		v.renderPermList("NotActions", "33", b.NotActions, full)
		v.renderPermList("DataActions", "94", b.DataActions, full)
		v.renderPermList("NotDataActions", "33", b.NotDataActions, full)
	}
}

func (v *view) renderRolePermissions(full bool) {
	s := v.active
	rbac := s.RBAC
	if rbac == nil {
		fmt.Fprintln(v.w, "no RBAC information available")
		return
	}

	seen := map[string]bool{}
	var roleNames []string
	for _, ra := range rbac.UserRoles {
		rn := roleDisplayName(ra)
		lk := strings.ToLower(rn)
		if !seen[lk] {
			seen[lk] = true
			roleNames = append(roleNames, rn)
		}
	}

	if len(roleNames) == 0 {
		fmt.Fprintf(v.w, "\n%s\n", v.p.c("1;36", "▸ Effective Subscription Permissions"))
		if rbac.UserRolesStatus == "denied" {
			fmt.Fprintln(v.w, "   "+v.p.c("33", "Role names unknown (Reader / roleAssignments/read required) — showing ARM effective permissions:"))
		}
		if rbac.Effective.Status == "ok" && len(rbac.Effective.Blocks) > 0 {
			fmt.Fprintf(v.w, "   %s\n", summarizeCapabilities(rbac.Effective.Blocks, ""))
			v.renderPermissionBlocks(rbac.Effective.Blocks, full)
		} else {
			fmt.Fprintln(v.w, "   "+v.p.c("33", "No permission data available in current mode/permissions."))
		}
		return
	}

	if v.online {
		ensureRoleDefs(s.Sub.ID, rbac, roleNames)
	}

	fmt.Fprintf(v.w, "\n%s\n", v.p.c("1;36", "▸ Permissions by Assigned Role"))
	for _, rn := range roleNames {
		rbac.mu.Lock()
		def := rbac.RoleDefs[strings.ToLower(rn)]
		rbac.mu.Unlock()
		if def == nil {
			fmt.Fprintf(v.w, "   • %s  %s\n", v.p.c(roleColorCode(rn), rn), v.p.c("2", "(definition not fetched / offline)"))
			continue
		}
		fmt.Fprintf(v.w, "\n   %s %s\n", v.p.c(roleColorCode(def.RoleName), "▸ "+def.RoleName), v.p.c("2", "["+def.RoleType+"]"))
		if def.Description != "" {
			fmt.Fprintf(v.w, "     %s\n", v.p.c("2", def.Description))
		}
		v.renderPermissionBlocks(def.Permissions, full)
	}
}

func (v *view) renderBundleRBAC(bundleNum int, full bool) {
	s := v.active
	if bundleNum < 1 || bundleNum > len(s.Groups) {
		fmt.Fprintf(v.w, "%s\n", v.p.c("31", fmt.Sprintf("bundle #%d out of range (1-%d)", bundleNum, len(s.Groups))))
		return
	}
	var g *Group
	for _, cand := range s.Groups {
		if s.BundleNo[cand.Anchor.Key] == bundleNum {
			g = cand
			break
		}
	}
	if g == nil {
		return
	}
	a := g.Anchor
	fmt.Fprintf(v.w, "\n%s  %s\n", v.p.c("1;36", fmt.Sprintf("▸ RBAC on Bundle #%d (%s)", bundleNum, a.Name)), v.p.c("2", shortType(a.Type)))

	scope := a.ID
	checkType := a.Type
	if a.Location == "deployment" || strings.EqualFold(a.Type, "Deployment/Batch") || !strings.HasPrefix(strings.ToLower(scope), "/subscriptions/") {
		if a.RG != "" && s.Sub.ID != "" {
			scope = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", s.Sub.ID, a.RG)
		} else {
			scope = "/subscriptions/" + s.Sub.ID
		}
		checkType = ""
	}
	fmt.Fprintf(v.w, "   %s %s\n", v.p.c("2", "scope:"), shortScope(scope, s.Sub.ID))

	rbac := s.RBAC
	var permRes *EffectivePermResult
	if rbac != nil {
		rbac.mu.Lock()
		if rbac.BundlePerms == nil {
			rbac.BundlePerms = map[string]*EffectivePermResult{}
		}
		permRes = rbac.BundlePerms[a.Key]
		rbac.mu.Unlock()

		if permRes == nil && v.online {
			fetched := fetchEffectivePerms(scope)
			permRes = &fetched
			rbac.mu.Lock()
			rbac.BundlePerms[a.Key] = permRes
			rbac.mu.Unlock()
		}
	}

	fmt.Fprintf(v.w, "\n   %s\n", v.p.c("1", "Your effective access on this bundle"))
	switch {
	case permRes != nil && permRes.Status == "ok":
		fmt.Fprintf(v.w, "   • %s\n", summarizeCapabilities(permRes.Blocks, checkType))
		v.renderPermissionBlocks(permRes.Blocks, full)
	case !v.online && rbac != nil && rbac.Effective.Status == "ok":
		fmt.Fprintf(v.w, "   • %s %s\n",
			summarizeCapabilities(rbac.Effective.Blocks, checkType),
			v.p.c("2", "(subscription-level offline estimate)"))
	case permRes != nil && permRes.Status == "denied":
		fmt.Fprintln(v.w, "   • "+v.p.c("33", "denied (requires Microsoft.Authorization/permissions/read)"))
	default:
		fmt.Fprintln(v.w, "   • "+v.p.c("2", "not available in offline mode"))
	}

	mis := collectBundleIdentities(g, s.Index.Res)
	fmt.Fprintf(v.w, "\n   %s\n", v.p.c("1;34", fmt.Sprintf("Managed identities in bundle · %d", len(mis))))
	if len(mis) == 0 {
		fmt.Fprintln(v.w, "   • "+v.p.c("2", "none detected"))
	} else {
		entries := make([]miTableEntry, 0, len(mis))
		for _, mi := range mis {
			entries = append(entries, miTableEntry{bundleNum: bundleNum, mi: mi})
		}
		v.renderMITable("   ", false, true, entries)
	}
}

// Interactive selection & loop

type selection struct {
	idx         []int
	all         bool
	ungrouped   bool
	quit        bool
	help        bool
	showList    bool
	showStatus  bool
	refresh     bool
	setFilter   bool
	filterVal   string
	rbacMode    string // "", "overview", "perms", "bundle"
	rbacBundle  int
	rbacFull    bool
	switchSub   bool
	switchQuery string
}

func parseSelection(line string, n int, hasFilter bool) (selection, error) {
	var s selection
	raw := strings.TrimSpace(line)
	if raw == "" {
		if hasFilter {
			return s, fmt.Errorf("type a bundle number (e.g. 1 or 2-4), l = list, st = status, '/' to clear filter, /search, r, a, u, ? or q")
		}
		return s, fmt.Errorf("type a bundle number (e.g. 1 or 2-4), l = list, st = status, /search, r, a, u, ? or q")
	}

	if strings.HasPrefix(raw, "/") {
		s.setFilter = true
		term := strings.TrimSpace(raw[1:])
		if strings.EqualFold(term, "clear") {
			term = ""
		}
		s.filterVal = term
		return s, nil
	}

	fields := strings.Fields(strings.ToLower(raw))
	switch fields[0] {
	case "?", "h", "help":
		s.help = true
		return s, nil
	case "l", "list", "ls":
		s.showList = true
		return s, nil
	case "st", "status":
		s.showStatus = true
		return s, nil
	case "refresh", "reload":
		s.refresh = true
		return s, nil
	case "s", "sub", "subs", "switch":
		s.switchSub = true
		if len(fields) > 1 {
			s.switchQuery = strings.Join(fields[1:], " ")
		}
		return s, nil
	case "rp":
		s.rbacMode = "perms"
		s.rbacFull = len(fields) > 1 && fields[1] == "full"
		return s, nil
	case "r", "rbac":
		if len(fields) == 1 {
			s.rbacMode = "overview"
			return s, nil
		}
		arg := fields[1]
		if arg == "perms" || arg == "perm" || arg == "permissions" || arg == "p" {
			s.rbacMode = "perms"
			s.rbacFull = len(fields) > 2 && fields[2] == "full"
			return s, nil
		}
		bNum, err := strconv.Atoi(arg)
		if err != nil {
			return s, fmt.Errorf("unknown r option %q (use 'r', 'r perms', 'r perms full', or 'r <bundle#>')", arg)
		}
		s.rbacMode = "bundle"
		s.rbacBundle = bNum
		s.rbacFull = len(fields) > 2 && fields[2] == "full"
		return s, nil
	}

	toks := strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	for _, t := range toks {
		switch t {
		case "q", "quit", "exit":
			s.quit = true
		case "a", "all":
			s.all = true
		case "u", "ungrouped":
			s.ungrouped = true
		default:
			var lo, hi int
			var err1, err2 error
			if i := strings.Index(t, "-"); i > 0 {
				lo, err1 = strconv.Atoi(t[:i])
				hi, err2 = strconv.Atoi(t[i+1:])
			} else {
				lo, err1 = strconv.Atoi(t)
				hi, err2 = lo, err1
			}
			if err1 != nil || err2 != nil || lo < 1 || hi > n || lo > hi {
				return s, fmt.Errorf("don't understand %q (valid bundle numbers are 1-%d, 'l' to list, or '?' for help)", t, n)
			}
			for i := lo; i <= hi; i++ {
				s.idx = append(s.idx, i-1)
			}
		}
	}
	return s, nil
}

func (v *view) promptText() string {
	parts := []string{"1,3 / 2-4", "l = list", "st = status"}
	if v.filter != "" {
		parts = append(parts, v.p.c("1;33", "/ = clear"), "/term")
	} else {
		parts = append(parts, "/term = search")
	}
	if v.online || (v.active != nil && v.active.RBAC != nil && v.active.RBAC.UserRolesStatus != "unavailable") {
		parts = append(parts, "r = rbac")
	}
	if v.online && len(v.subs) > 1 {
		parts = append(parts, fmt.Sprintf("s = sub (%d)", len(v.subs)))
	}
	parts = append(parts, "a = all", "u = ungrouped", "? = help", "q = quit")
	prefix := "\nshow: "
	if v.filter != "" {
		prefix = fmt.Sprintf("\nshow [filter: %s]: ", v.p.c("1;34", v.filter))
	}
	return prefix + strings.Join(parts, " · ") + " > "
}

func (v *view) printHelp() {
	fmt.Fprintf(v.w, "\n%s\n", v.p.c("1;36", "▸ Commands"))
	fmt.Fprintln(v.w, "   1,3 or 2-4     Inspect bundle(s) by number")
	fmt.Fprintln(v.w, "   l              List bundles")
	fmt.Fprintln(v.w, "   st             Show status (subscription, user, RBAC, filter)")
	fmt.Fprintln(v.w, "   /term          Filter bundles (matches name, type, RG, creator)")
	fmt.Fprintln(v.w, "   /new · /mi     Filter to bundles with new resources or Managed Identities")
	fmt.Fprintln(v.w, "   / or /clear    Clear active search filter")
	fmt.Fprintln(v.w, "   r              RBAC overview (your roles + Managed Identities)")
	fmt.Fprintln(v.w, "   r perms        List permissions per role ('r perms full' for all actions)")
	fmt.Fprintln(v.w, "   r <bundle#>    Check effective permissions & Managed Identities for a bundle")
	if v.online && len(v.subs) > 1 {
		fmt.Fprintln(v.w, "   s [num|name]   Switch Azure subscription (runs az account set)")
	}
	if v.online {
		fmt.Fprintln(v.w, "   refresh        Re-scan the current subscription")
	}
	fmt.Fprintln(v.w, "   a · u · q      Dump all visible bundles · Show ungrouped · Quit")
}

func (v *view) handleSwitchSub(in *bufio.Reader, preQuery string) bool {
	if !v.online {
		fmt.Fprintln(v.w, v.p.c("33", "subscription switching is disabled in offline mode"))
		return false
	}
	if len(v.subs) <= 1 {
		fmt.Fprintln(v.w, v.p.c("2", "only 1 subscription available"))
		return false
	}

	pick := strings.TrimSpace(preQuery)
	if pick == "" {
		fmt.Fprintf(v.w, "\n%s\n", v.p.c("1;36", "▸ Available Subscriptions"))
		for i, sub := range v.subs {
			cur, tag := " ", ""
			if strings.EqualFold(sub.ID, v.active.Sub.ID) {
				cur = v.p.c("1;32", "*")
				tag = " " + v.p.c("1;32", "[current]")
			} else if _, cached := v.cache[strings.ToLower(sub.ID)]; cached {
				tag = " " + v.p.c("94", "[cached]")
			}
			fmt.Fprintf(v.w, "  %s [%2d] %s  %s%s\n", cur, i+1, padRight(sub.Name, 30), v.p.c("2", sub.ID), tag)
		}
		fmt.Fprint(v.w, "\nswitch to (number, name, or Enter to cancel) > ")
		line, _ := in.ReadString('\n')
		pick = strings.TrimSpace(line)
		if pick == "" {
			return false
		}
	}

	var target *Subscription
	if idx, err := strconv.Atoi(pick); err == nil {
		if idx >= 1 && idx <= len(v.subs) {
			target = &v.subs[idx-1]
		}
	} else {
		lp := strings.ToLower(pick)
		for i := range v.subs {
			if strings.EqualFold(v.subs[i].ID, pick) || strings.EqualFold(v.subs[i].Name, pick) {
				target = &v.subs[i]
				break
			}
		}
		if target == nil {
			for i := range v.subs {
				if strings.Contains(strings.ToLower(v.subs[i].Name), lp) {
					target = &v.subs[i]
					break
				}
			}
		}
	}

	if target == nil {
		fmt.Fprintln(v.w, v.p.c("31", fmt.Sprintf("subscription %q not found", pick)))
		return false
	}
	if strings.EqualFold(target.ID, v.active.Sub.ID) {
		fmt.Fprintln(v.w, v.p.c("2", "already on "+target.Name))
		return false
	}

	if !v.opts.noState {
		saveLastRun(v.active.Sub.ID, time.Now().UTC())
	}

	fmt.Fprintf(os.Stderr, "switching active subscription to %s (%s) ...\n", target.Name, target.ID)
	if _, err := azRun("account", "set", "--subscription", target.ID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: az account set failed (%v)\n", err)
	}

	k := strings.ToLower(target.ID)
	next, ok := v.cache[k]
	if !ok {
		var err error
		next, _, err = scanOnlineSub(*target, v.oid, v.opts)
		if err != nil {
			fmt.Fprintln(v.w, v.p.c("31", "failed to load subscription: "+err.Error()))
			return false
		}
		v.cache[k] = next
	} else if !v.opts.hasSince && !v.opts.noState {
		next.Since = loadLastRun(target.ID)
	}

	v.active = next
	v.filter = ""
	return true
}

func (v *view) run() {
	in := bufio.NewReader(os.Stdin)
	v.status()
	v.list()

	for {
		fmt.Fprint(v.w, v.promptText())
		line, err := in.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			fmt.Fprintln(v.w)
			return
		}
		sel, perr := parseSelection(line, len(v.active.Groups), v.filter != "")
		if perr != nil {
			fmt.Fprintln(v.w, v.p.c("31", perr.Error()))
			continue
		}
		switch {
		case sel.quit:
			return
		case sel.help:
			v.printHelp()
		case sel.showList:
			v.list()
		case sel.showStatus:
			v.status()
		case sel.setFilter:
			v.filter = sel.filterVal
			v.list()
		case sel.switchSub:
			if v.handleSwitchSub(in, sel.switchQuery) {
				v.status()
				v.list()
			}
		case sel.refresh:
			if !v.online {
				fmt.Fprintln(v.w, v.p.c("33", "refresh is disabled in offline mode"))
				continue
			}
			fmt.Fprintf(os.Stderr, "re-scanning %s ...\n", v.active.Sub.Name)
			refreshed, _, rerr := scanOnlineSub(v.active.Sub, v.oid, v.opts)
			if rerr != nil {
				fmt.Fprintln(v.w, v.p.c("31", "refresh failed: "+rerr.Error()))
				continue
			}
			v.active = refreshed
			v.cache[strings.ToLower(refreshed.Sub.ID)] = refreshed
			v.status()
			v.list()
		case sel.rbacMode == "overview":
			v.renderRBACOverview()
		case sel.rbacMode == "perms":
			v.renderRolePermissions(sel.rbacFull)
		case sel.rbacMode == "bundle":
			v.renderBundleRBAC(sel.rbacBundle, sel.rbacFull)
		case sel.all:
			v.dump(v.filteredGroups(), v.active.Ungrouped, false)
		default:
			for _, i := range sel.idx {
				v.group(v.active.Groups[i])
			}
			if sel.ungrouped {
				if len(v.active.Ungrouped) == 0 {
					fmt.Fprintln(v.w, "nothing is ungrouped")
				} else {
					v.ungrouped(v.active.Ungrouped)
				}
			}
		}
	}
}

// Azure CLI callers & loaders

const graphQuery = "resources | project id, name, type, resourceGroup, location, managedBy, identity, properties, systemData | order by id asc"
const deploymentsQuery = "resourcecontainers | where type =~ 'microsoft.resources/deployments' | project id, name, resourceGroup, properties | order by todatetime(properties.timestamp) desc"

func ensureLogin(force bool) error {
	if !force {
		if exec.Command("az", "account", "show").Run() == nil {
			return nil
		}
		fmt.Fprintln(os.Stderr, "Azure CLI is not logged in or session expired.")
	}
	fmt.Fprintln(os.Stderr, "Running 'az login' ...")
	cmd := exec.Command("az", "login")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("az login failed: %w", err)
	}
	return nil
}

func azRun(args ...string) ([]byte, error) {
	cmd := exec.Command("az", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("az %s failed: %v\n%s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func tokenOID() string {
	b, err := azRun("account", "get-access-token", "--query", "accessToken", "-o", "tsv")
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		OID string `json:"oid"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.OID
}

func fetchSubscriptions() ([]Subscription, error) {
	b, err := azRun("account", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var all []Subscription
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var enabled []Subscription
	for _, s := range all {
		if s.State == "" || strings.EqualFold(s.State, "Enabled") {
			enabled = append(enabled, s)
		}
	}
	sort.SliceStable(enabled, func(i, j int) bool {
		return strings.ToLower(enabled[i].Name) < strings.ToLower(enabled[j].Name)
	})
	return enabled, nil
}

func resolveActiveSubscription(requested string, subs []Subscription) (Subscription, error) {
	if requested != "" {
		for _, s := range subs {
			if strings.EqualFold(s.ID, requested) || strings.EqualFold(s.Name, requested) {
				return s, nil
			}
		}
		return Subscription{ID: requested, Name: requested}, nil
	}
	for _, s := range subs {
		if s.IsDefault {
			return s, nil
		}
	}
	b, err := azRun("account", "show", "-o", "json")
	if err != nil {
		return Subscription{}, err
	}
	var cur Subscription
	if err := json.Unmarshal(b, &cur); err != nil {
		return Subscription{}, err
	}
	return cur, nil
}

func parseGraphData[T any](b []byte) ([]T, error) {
	var env struct {
		Data []T `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err == nil && env.Data != nil {
		return env.Data, nil
	}
	var arr []T
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

func fetchGraphPaged[T any](sub, query string) ([]T, error) {
	const page = 1000
	var all []T
	for skip := 0; ; skip += page {
		b, err := azRun("graph", "query", "-q", query, "--subscriptions", sub,
			"--first", strconv.Itoa(page), "--skip", strconv.Itoa(skip), "-o", "json")
		if err != nil {
			return nil, err
		}
		items, err := parseGraphData[T](b)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) < page {
			return all, nil
		}
	}
}

func fetchEffectivePerms(scope string) EffectivePermResult {
	scope = strings.TrimRight(scope, "/")
	url := scope + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
	b, err := azRun("rest", "--method", "get", "--url", url)
	if err != nil {
		if hasAuthDenied(err) {
			return EffectivePermResult{Status: "denied", Scope: scope, Error: "Microsoft.Authorization/permissions/read required"}
		}
		return EffectivePermResult{Status: "error", Scope: scope, Error: err.Error()}
	}
	var res struct {
		Value []PermissionBlock `json:"value"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return EffectivePermResult{Status: "error", Scope: scope, Error: err.Error()}
	}
	return EffectivePermResult{Status: "ok", Scope: scope, Blocks: res.Value}
}

func fetchCallerRoleAssignments(sub string, caller AccountUser, oid string) (string, []RoleAssignment, string) {
	var b []byte
	var err error
	if oid != "" {
		b, err = azRun("role", "assignment", "list", "--assignee-object-id", oid,
			"--all", "--include-inherited", "--include-groups", "--fill-principal-name", "false",
			"--subscription", sub, "-o", "json")
		if err != nil && !hasAuthDenied(err) && hasGraphDenied(err) {
			b, err = azRun("role", "assignment", "list", "--assignee-object-id", oid,
				"--all", "--include-inherited", "--fill-principal-name", "false",
				"--subscription", sub, "-o", "json")
		}
	} else if caller.Name != "" {
		b, err = azRun("role", "assignment", "list", "--assignee", caller.Name,
			"--all", "--include-inherited", "--include-groups",
			"--subscription", sub, "-o", "json")
	} else {
		return "unavailable", nil, ""
	}

	if err != nil {
		if hasAuthDenied(err) {
			return "denied", nil, "Reader role / Microsoft.Authorization/roleAssignments/read required"
		}
		return "error", nil, err.Error()
	}
	var ras []RoleAssignment
	if err := json.Unmarshal(b, &ras); err != nil {
		return "error", nil, err.Error()
	}
	sortRoleAssignments(ras)
	return "ok", ras, ""
}

func fetchAllSubRoleAssignments(sub string) (string, []RoleAssignment, string) {
	b, err := azRun("role", "assignment", "list", "--all", "--include-inherited",
		"--fill-principal-name", "false", "--subscription", sub, "-o", "json")
	if err != nil {
		if hasAuthDenied(err) {
			return "denied", nil, "Reader role / Microsoft.Authorization/roleAssignments/read required"
		}
		return "error", nil, err.Error()
	}
	var ras []RoleAssignment
	if err := json.Unmarshal(b, &ras); err != nil {
		return "error", nil, err.Error()
	}
	return "ok", ras, ""
}

func fetchRBAC(sub string, caller AccountUser, oid string) *RBACData {
	rbac := &RBACData{
		Caller:      caller,
		CallerOID:   oid,
		ByPrincipal: map[string][]RoleAssignment{},
		RoleDefs:    map[string]*RoleDefinition{},
		BundlePerms: map[string]*EffectivePermResult{},
	}

	var allRAs []RoleAssignment
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		rbac.UserRolesStatus, rbac.UserRoles, rbac.UserRolesErr = fetchCallerRoleAssignments(sub, caller, oid)
	}()
	go func() {
		defer wg.Done()
		rbac.AllRolesStatus, allRAs, rbac.AllRolesErr = fetchAllSubRoleAssignments(sub)
	}()
	go func() {
		defer wg.Done()
		rbac.Effective = fetchEffectivePerms("/subscriptions/" + sub)
	}()
	wg.Wait()

	if rbac.AllRolesStatus == "ok" {
		rbac.ByPrincipal = indexByPrincipal(allRAs)
		if rbac.UserRolesStatus == "error" && oid != "" {
			if direct, ok := rbac.ByPrincipal[strings.ToLower(oid)]; ok {
				rbac.UserRolesStatus = "ok"
				rbac.UserRoles = direct
				rbac.UserRolesErr = ""
			}
		}
	}
	return rbac
}

func ensureRoleDefs(sub string, rbac *RBACData, roleNames []string) {
	var missing []string
	rbac.mu.Lock()
	if rbac.RoleDefs == nil {
		rbac.RoleDefs = map[string]*RoleDefinition{}
	}
	for _, rn := range roleNames {
		if _, ok := rbac.RoleDefs[strings.ToLower(rn)]; !ok {
			missing = append(missing, rn)
		}
	}
	rbac.mu.Unlock()
	if len(missing) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "fetching %d role definition(s) ...\n", len(missing))
	jobs := make(chan string, len(missing))
	for _, rn := range missing {
		jobs <- rn
	}
	close(jobs)

	workers := min(6, len(missing))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rn := range jobs {
				b, err := azRun("role", "definition", "list", "--name", rn, "--subscription", sub, "-o", "json")
				if err != nil || len(bytes.TrimSpace(b)) <= 2 {
					b, err = azRun("role", "definition", "list", "--name", rn, "-o", "json")
				}
				if err != nil {
					continue
				}
				var defs []RoleDefinition
				if json.Unmarshal(b, &defs) == nil && len(defs) > 0 {
					d := defs[0]
					rbac.mu.Lock()
					rbac.RoleDefs[strings.ToLower(rn)] = &d
					rbac.mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
}

// sub scan & offline assembly

func buildSession(sub Subscription, list []listItem, graph []graphItem, deps []deploymentItem, savedExtra []*Resource, rbac *RBACData, opts scanOpts, online bool) (*SubSession, []*Resource) {
	resources := merge(list, graph)
	var extraOnline []*Resource
	if opts.deep {
		if len(savedExtra) > 0 {
			resources, _ = expandSubresources(sub.ID, resources, true, false)
			existing := make(map[string]bool, len(resources))
			for _, r := range resources {
				existing[r.Key] = true
			}
			for _, ex := range savedExtra {
				if ex != nil && ex.Key != "" && !existing[ex.Key] {
					existing[ex.Key] = true
					resources = append(resources, ex)
				}
			}
		} else {
			resources, extraOnline = expandSubresources(sub.ID, resources, opts.deep, online)
		}
	}

	ix := buildIndex(resources)
	groups, ungrouped := buildGroups(ix, resources, deps, opts.depth, opts.window)
	sort.SliceStable(groups, func(i, j int) bool { return newer(groups[i].Anchor.Created, groups[j].Anchor.Created) })

	bundleNo := make(map[string]int, len(groups))
	for i, g := range groups {
		bundleNo[g.Anchor.Key] = i + 1
	}

	var since time.Time
	switch {
	case opts.hasSince:
		since = opts.since
	case !opts.noState:
		since = loadLastRun(sub.ID)
	}

	return &SubSession{
		Sub:       sub,
		Resources: resources,
		Index:     ix,
		Groups:    groups,
		Ungrouped: ungrouped,
		Shared:    countShared(groups),
		BundleNo:  bundleNo,
		RBAC:      rbac,
		Since:     since,
		ScannedAt: time.Now().UTC(),
	}, extraOnline
}

func scanOnlineSub(sub Subscription, oid string, opts scanOpts) (*SubSession, *Snapshot, error) {
	fmt.Fprintf(os.Stderr, "scanning %s (%s)...\n", sub.Name, sub.ID)

	var (
		list     []listItem
		listErr  error
		graph    []graphItem
		graphErr error
		deps     []deploymentItem
		rbac     *RBACData
		wg       sync.WaitGroup
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		b, err := azRun("resource", "list", "--subscription", sub.ID, "-o", "json")
		if err != nil {
			listErr = err
			return
		}
		if err := json.Unmarshal(b, &list); err != nil {
			listErr = fmt.Errorf("parsing az resource list output: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		graph, graphErr = fetchGraphPaged[graphItem](sub.ID, graphQuery)
	}()

	if opts.deployments {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, err := fetchGraphPaged[deploymentItem](sub.ID, deploymentsQuery); err == nil {
				deps = d
			}
		}()
	}

	if opts.rbac {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rbac = fetchRBAC(sub.ID, sub.User, oid)
		}()
	} else {
		rbac = &RBACData{
			Caller:          sub.User,
			UserRolesStatus: "unavailable",
			AllRolesStatus:  "unavailable",
			Effective:       EffectivePermResult{Status: "unavailable"},
		}
	}

	wg.Wait()

	if listErr != nil {
		return nil, nil, listErr
	}
	if graphErr != nil {
		fmt.Fprintf(os.Stderr, "warning: Resource Graph unavailable (%v)\n  falling back to timestamps only. Try: az extension add --name resource-graph\n", graphErr)
	}

	sess, extraOnline := buildSession(sub, list, graph, deps, nil, rbac, opts, true)
	snap := &Snapshot{
		Version:      1,
		CapturedAt:   sess.ScannedAt,
		Subscription: sub,
		List:         list,
		Graph:        graph,
		Deployments:  deps,
		Subresources: extraOnline,
		RBAC:         rbac,
	}
	return sess, snap, nil
}

func loadOfflineFiles(opts scanOpts) (*SubSession, error) {
	if opts.snapshotFile != "" {
		b, err := os.ReadFile(opts.snapshotFile)
		if err != nil {
			return nil, err
		}
		var snap Snapshot
		if err := json.Unmarshal(b, &snap); err != nil {
			return nil, fmt.Errorf("%s: %v", opts.snapshotFile, err)
		}
		if snap.RBAC == nil {
			snap.RBAC = &RBACData{
				UserRolesStatus: "unavailable",
				AllRolesStatus:  "unavailable",
				Effective:       EffectivePermResult{Status: "unavailable"},
			}
		}
		if snap.Subscription.ID == "" {
			snap.Subscription.ID = "offline"
			snap.Subscription.Name = filepath.Base(opts.snapshotFile)
		}
		sess, _ := buildSession(snap.Subscription, snap.List, snap.Graph, snap.Deployments, snap.Subresources, snap.RBAC, opts, false)
		return sess, nil
	}

	b, err := os.ReadFile(opts.listFile)
	if err != nil {
		return nil, err
	}
	var list []listItem
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %v", opts.listFile, err)
	}

	var graph []graphItem
	if opts.graphFile != "" {
		gb, err := os.ReadFile(opts.graphFile)
		if err != nil {
			return nil, err
		}
		if graph, err = parseGraphData[graphItem](gb); err != nil {
			return nil, fmt.Errorf("%s: %v", opts.graphFile, err)
		}
	}

	var deps []deploymentItem
	if opts.deploymentsFile != "" {
		if db, err := os.ReadFile(opts.deploymentsFile); err == nil {
			deps, _ = parseGraphData[deploymentItem](db)
		}
	}

	rbac := &RBACData{
		UserRolesStatus: "unavailable",
		AllRolesStatus:  "unavailable",
		Effective:       EffectivePermResult{Status: "unavailable"},
		ByPrincipal:     map[string][]RoleAssignment{},
		RoleDefs:        map[string]*RoleDefinition{},
	}
	if opts.rbacFile != "" {
		rb, err := os.ReadFile(opts.rbacFile)
		if err != nil {
			return nil, err
		}
		var fullRBAC RBACData
		if json.Unmarshal(rb, &fullRBAC) == nil && fullRBAC.UserRolesStatus != "" {
			rbac = &fullRBAC
		} else {
			var ras []RoleAssignment
			if err := json.Unmarshal(rb, &ras); err != nil {
				return nil, fmt.Errorf("%s: %v", opts.rbacFile, err)
			}
			sortRoleAssignments(ras)
			rbac.UserRolesStatus = "ok"
			rbac.UserRoles = ras
			rbac.AllRolesStatus = "ok"
			rbac.ByPrincipal = indexByPrincipal(ras)
		}
	}

	sub := Subscription{ID: "offline", Name: "offline (" + filepath.Base(opts.listFile) + ")"}
	sess, _ := buildSession(sub, list, graph, deps, nil, rbac, opts, false)
	return sess, nil
}

func saveSnapshot(path string, snap *Snapshot) error {
	if snap == nil {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Per-subscription state persistence

type stateFile struct {
	LastRun time.Time            `json:"lastRun,omitempty"` // backwards compat
	BySub   map[string]time.Time `json:"bySub,omitempty"`
}

func statePath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "azsift", "state.json")
}

func readState() stateFile {
	p := statePath()
	if p == "" {
		return stateFile{}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return stateFile{}
	}
	var s stateFile
	if json.Unmarshal(b, &s) != nil {
		return stateFile{}
	}
	return s
}

func loadLastRun(subID string) time.Time {
	s := readState()
	if subID != "" && s.BySub != nil {
		if t, ok := s.BySub[strings.ToLower(subID)]; ok {
			return t
		}
	}
	return s.LastRun
}

func saveLastRun(subID string, t time.Time) {
	p := statePath()
	if p == "" || os.MkdirAll(filepath.Dir(p), 0o755) != nil {
		return
	}
	s := readState()
	if s.BySub == nil {
		s.BySub = map[string]time.Time{}
	}
	if subID != "" {
		s.BySub[strings.ToLower(subID)] = t
	}
	s.LastRun = t
	if b, err := json.Marshal(s); err == nil {
		_ = os.WriteFile(p, b, 0o644)
	}
}

func parseSince(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("--since %q: use 2026-10-01, an RFC3339 time, or a duration like 72h", s)
}

func printFlagGroup(title string, names ...string) {
	fmt.Fprintf(os.Stderr, "\n%s:\n", title)
	for _, name := range names {
		f := flag.Lookup(name)
		if f == nil {
			continue
		}
		placeholder, desc := flag.UnquoteUsage(f)
		spec := "-" + f.Name
		if placeholder != "" {
			spec += " " + placeholder
		}
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" {
			desc += fmt.Sprintf(" (default: %s)", f.DefValue)
		}
		fmt.Fprintf(os.Stderr, "  %-22s %s\n", spec, desc)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// main

func printUsage() {
	fmt.Fprintf(os.Stderr, `azsift - Interactive mapper for Azure resource bundles and RBAC.

USAGE:
  azsift [flags]

EXAMPLES:
  azsift -login                     # Run az login first, then scan current subscription
  azsift -sub <sub-id>              # Target a specific subscription
  azsift -all                       # Non-interactive: dump all bundles to stdout
  azsift -save snap.json            # Scan online & save full snapshot
  azsift -f snap.json               # Inspect a saved snapshot completely offline
`)
	printFlagGroup("SCAN & TARGET", "sub", "login", "save")
	printFlagGroup("OFFLINE INPUT", "f", "listf", "graphf", "deployf", "rbacf")
	printFlagGroup("GROUPING & DISCOVERY", "window", "subwindow", "depth", "deep", "deployments", "rbac")
	printFlagGroup("OUTPUT & STATE", "all", "since", "no-state", "no-color")
	fmt.Fprintln(os.Stderr)
}

func main() {
	login := flag.Bool("login", false, "run 'az login' before scanning")
	sub := flag.String("sub", "", "target subscription `<id|name>` (default: current az account)")
	all := flag.Bool("all", false, "dump every bundle and exit (non-interactive)")
	listFile := flag.String("listf", "", "read 'az resource list -o json' output from `<file>`")
	graphFile := flag.String("graphf", "", "read 'az graph query -o json' output from `<file>`")
	deploymentsFile := flag.String("deployf", "", "read deployment query output from `<file>`")
	rbacFile := flag.String("rbacf", "", "read RBAC JSON or 'az role assignment list -o json' from `<file>`")
	snapshotFile := flag.String("f", "", "inspect snapshot `<file>` saved via -save")
	saveSnapPath := flag.String("save", "", "save full scan snapshot (resources, graph, deployments, RBAC) to `<file>`")
	window := flag.Duration("window", 30*time.Minute, "max `<dur>` gap to cluster resources created together (0 disables)")
	depth := flag.Int("depth", 2, "follow up to `<n>` reference hops from an anchor resource")
	subWindow := flag.Duration("subwindow", 15*time.Minute, "max `<dur>` gap to bracket sub-resources (0 disables)")
	deep := flag.Bool("deep", true, "discover deeper sub-resources (blob containers, subnets)")
	deploymentsFlag := flag.Bool("deployments", true, "group resources by ARM/Bicep template deployments")
	rbacFlag := flag.Bool("rbac", true, "detect RBAC roles & managed identity assignments when online")
	sinceFlag := flag.String("since", "", "mark resources created after `<time|dur>` (e.g. 2026-10-01, 72h; default: last run)")
	noState := flag.Bool("no-state", false, "don't read or write the last-run state file")
	noColor := flag.Bool("no-color", false, "disable ANSI colors")

	flag.Usage = printUsage
	flag.Parse()

	if *snapshotFile != "" && *listFile != "" {
		fatal(fmt.Errorf("cannot combine -f and -listf"))
	}

	opts := scanOpts{
		window:          *window,
		depth:           *depth,
		subWindow:       *subWindow,
		deep:            *deep,
		deployments:     *deploymentsFlag,
		rbac:            *rbacFlag,
		noState:         *noState,
		listFile:        *listFile,
		graphFile:       *graphFile,
		deploymentsFile: *deploymentsFile,
		rbacFile:        *rbacFile,
		snapshotFile:    *snapshotFile,
	}
	if *sinceFlag != "" {
		t, err := parseSince(*sinceFlag)
		if err != nil {
			fatal(err)
		}
		opts.since = t
		opts.hasSince = true
	}

	online := *listFile == "" && *snapshotFile == ""

	v := &view{
		w:         os.Stdout,
		p:         palette{on: useColor(*noColor)},
		online:    online,
		cache:     map[string]*SubSession{},
		opts:      opts,
		subWindow: *subWindow,
	}

	if online {
		if err := ensureLogin(*login); err != nil {
			fatal(err)
		}

		var subs []Subscription
		var subsErr error
		var oid string
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			subs, subsErr = fetchSubscriptions()
		}()
		go func() {
			defer wg.Done()
			if *rbacFlag {
				oid = tokenOID()
			}
		}()
		wg.Wait()

		if subsErr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not list subscriptions (%v)\n", subsErr)
		}
		targetSub, err := resolveActiveSubscription(*sub, subs)
		if err != nil {
			fatal(err)
		}

		sess, snap, err := scanOnlineSub(targetSub, oid, opts)
		if err != nil {
			fatal(err)
		}
		if *saveSnapPath != "" {
			if err := saveSnapshot(*saveSnapPath, snap); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to save snapshot %s: %v\n", *saveSnapPath, err)
			} else {
				fmt.Fprintf(os.Stderr, "saved snapshot to %s\n", *saveSnapPath)
			}
		}

		v.subs = subs
		v.oid = oid
		v.active = sess
		v.cache[strings.ToLower(targetSub.ID)] = sess
	} else {
		sess, err := loadOfflineFiles(opts)
		if err != nil {
			fatal(err)
		}
		v.active = sess
	}

	if len(v.active.Resources) == 0 {
		fmt.Println("no resources found")
		return
	}

	if *all {
		v.dump(v.active.Groups, v.active.Ungrouped, true)
	} else {
		v.run()
	}

	if !*noState && v.active != nil {
		saveLastRun(v.active.Sub.ID, time.Now().UTC())
	}
}
