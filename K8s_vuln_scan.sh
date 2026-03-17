#!/usr/bin/env bash
# =============================================================================
# k8s_vuln_scan.sh — Kubernetes Critical & High Vulnerability Scanner
# AKS / Azure-focused | Native kubectl only (no external tools required)
# =============================================================================
# Usage:
#   ./k8s_vuln_scan.sh                        # scan all namespaces
#   ./k8s_vuln_scan.sh -n my-namespace        # specific namespace
#   ./k8s_vuln_scan.sh -o report.txt          # save findings to file
#   ./k8s_vuln_scan.sh -n prod -o out.txt     # both
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Globals ───────────────────────────────────────────────────────────────────
NS_FLAG="--all-namespaces"
NS_LABEL="all namespaces"
OUTPUT_FILE=""
CRITICAL_COUNT=0
HIGH_COUNT=0
PASS_COUNT=0
declare -a FINDINGS=()

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NS_FLAG="-n $2"; NS_LABEL="$2"; shift 2 ;;
    -o|--output)    OUTPUT_FILE="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [-n <namespace>] [-o <output-file>]"
      exit 0 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# ── Logging helpers ───────────────────────────────────────────────────────────
log()  { echo -e "${DIM}[…] $*${RESET}"; }
pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo -e "${GREEN}[PASS]${RESET}     $*"
}
critical() {
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
  FINDINGS+=("CRITICAL | $*")
  echo -e "${RED}${BOLD}[CRITICAL]${RESET} $*"
}
high() {
  HIGH_COUNT=$((HIGH_COUNT + 1))
  FINDINGS+=("HIGH     | $*")
  echo -e "${ORANGE}${BOLD}[HIGH]${RESET}     $*"
}
section() {
  echo ""
  echo -e "${BOLD}${BLUE}┌──────────────────────────────────────────────────────┐${RESET}"
  printf "${BOLD}${BLUE}│${RESET}  %-52s${BOLD}${BLUE}│${RESET}\n" "$*"
  echo -e "${BOLD}${BLUE}└──────────────────────────────────────────────────────┘${RESET}"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
preflight() {
  if ! command -v kubectl &>/dev/null; then
    echo -e "${RED}kubectl not found. Please install kubectl and configure kubeconfig.${RESET}"
    exit 1
  fi
  if ! kubectl cluster-info &>/dev/null 2>&1; then
    echo -e "${RED}Cannot reach cluster. Check your kubeconfig / AKS credentials.${RESET}"
    echo -e "${DIM}Hint: az aks get-credentials --resource-group <rg> --name <cluster>${RESET}"
    exit 1
  fi
  if ! command -v python3 &>/dev/null; then
    echo -e "${RED}python3 is required for JSON parsing. Please install it.${RESET}"
    exit 1
  fi
}

# =============================================================================
# 1. RBAC
# =============================================================================
check_rbac() {
  section "1/9 · RBAC Misconfigurations"

  # ── 1a. cluster-admin bindings ──────────────────────────────────────────────
  log "Checking ClusterRoleBindings for cluster-admin..."
  local _out
  _out=$(kubectl get clusterrolebindings -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
data = json.load(sys.stdin)
found = False
for crb in data.get('items', []):
    role  = crb.get('roleRef', {}).get('name', '')
    cname = crb.get('metadata', {}).get('name', '')
    if role != 'cluster-admin':
        continue
    for subj in (crb.get('subjects') or []):
        kind  = subj.get('kind','')
        sname = subj.get('name','')
        ns    = subj.get('namespace','cluster-wide')
        if sname in ('system:anonymous','system:unauthenticated'):
            print(f'CRITICAL|cluster-admin granted to {sname} via binding "{cname}"')
        elif kind == 'ServiceAccount':
            print(f'CRITICAL|cluster-admin granted to ServiceAccount "{sname}" (ns: {ns}) via "{cname}"')
        elif kind in ('User','Group') and 'system:' not in sname:
            print(f'HIGH|cluster-admin granted to {kind} "{sname}" via "{cname}"')
        found = True
if not found:
    print('PASS|No unexpected cluster-admin bindings found')
PYEOF
)
  echo "$_out" | while IFS='|' read -r sev msg; do
    case "$sev" in CRITICAL) critical "$msg";; HIGH) high "$msg";; PASS) pass "$msg";; esac
  done

  # ── 1b. Wildcard permissions ────────────────────────────────────────────────
  log "Checking ClusterRoles for wildcard (*) permissions..."
  local _wc
  _wc=$(kubectl get clusterroles -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
data = json.load(sys.stdin)
skip_prefixes = ('system:','kubeadm:','calico','azure','aks','omsagent')
found = False
for cr in data.get('items', []):
    name = cr.get('metadata',{}).get('name','')
    if any(name.startswith(p) for p in skip_prefixes) or name == 'cluster-admin':
        continue
    for rule in (cr.get('rules') or []):
        if '*' in rule.get('verbs', []) and '*' in rule.get('resources', []):
            print(f'HIGH|ClusterRole "{name}" grants full wildcard (*) on all resources and verbs')
            found = True
            break
if not found:
    print('PASS|No non-system ClusterRoles with wildcard permissions')
PYEOF
)
  echo "$_wc" | while IFS='|' read -r sev msg; do
    case "$sev" in HIGH) high "$msg";; PASS) pass "$msg";; esac
  done

  # ── 1c. Anonymous access via RBAC ───────────────────────────────────────────
  log "Checking for RBAC rules granting access to unauthenticated users..."
  local _anon
  _anon=$(kubectl get clusterrolebindings -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
data = json.load(sys.stdin)
found = False
for crb in data.get('items', []):
    cname = crb.get('metadata',{}).get('name','')
    for subj in (crb.get('subjects') or []):
        if subj.get('name','') in ('system:anonymous','system:unauthenticated'):
            role = crb.get('roleRef',{}).get('name','')
            print(f'CRITICAL|ClusterRoleBinding "{cname}" grants role "{role}" to anonymous/unauthenticated')
            found = True
if not found:
    print('PASS|No RBAC bindings for anonymous/unauthenticated users')
PYEOF
)
  echo "$_anon" | while IFS='|' read -r sev msg; do
    case "$sev" in CRITICAL) critical "$msg";; PASS) pass "$msg";; esac
  done

  # ── 1d. Default SA with elevated RoleBindings ──────────────────────────────
  log "Checking for non-default RoleBindings on 'default' ServiceAccounts..."
  local _defsa
  _defsa=$(kubectl get rolebindings $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
data = json.load(sys.stdin)
found = False
for rb in data.get('items', []):
    ns   = rb.get('metadata',{}).get('namespace','?')
    rname= rb.get('metadata',{}).get('name','?')
    role = rb.get('roleRef',{}).get('name','')
    for subj in (rb.get('subjects') or []):
        if subj.get('kind') == 'ServiceAccount' and subj.get('name') == 'default':
            print(f'HIGH|Default ServiceAccount in ns "{ns}" has RoleBinding "{rname}" (role: {role})')
            found = True
if not found:
    print('PASS|No elevated RoleBindings on default ServiceAccounts')
PYEOF
)
  echo "$_defsa" | while IFS='|' read -r sev msg; do
    case "$sev" in HIGH) high "$msg";; PASS) pass "$msg";; esac
  done
}

# =============================================================================
# 2. PRIVILEGED & UNSAFE WORKLOADS
# =============================================================================
check_privileged_workloads() {
  section "2/9 · Privileged & Unsafe Workloads"

  log "Scanning all pods for security context issues..."
  kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json

DANGEROUS_CAPS = {'SYS_ADMIN','NET_ADMIN','SYS_PTRACE','SYS_MODULE',
                  'DAC_OVERRIDE','DAC_READ_SEARCH','SYS_RAWIO',
                  'SYS_BOOT','SYS_NICE','MKNOD','ALL'}
DANGEROUS_HOST_PATHS = {'/','/etc','/root','/proc','/sys',
                        '/var/run/docker.sock','/var/run/crio.sock',
                        '/run/containerd','/var/lib/kubelet'}

data   = json.load(sys.stdin)
issues = []
ok     = 0

for pod in data.get('items', []):
    meta = pod.get('metadata', {})
    name = meta.get('name','?')
    ns   = meta.get('namespace','?')
    spec = pod.get('spec', {})
    ref  = f'{ns}/{name}'

    if spec.get('hostNetwork'): issues.append(f'HIGH|{ref}|hostNetwork=true (bypasses NetworkPolicy)')
    if spec.get('hostPID'):     issues.append(f'HIGH|{ref}|hostPID=true (can inspect host processes)')
    if spec.get('hostIPC'):     issues.append(f'HIGH|{ref}|hostIPC=true (shared IPC namespace)')

    psc = spec.get('securityContext', {})
    if psc.get('runAsUser') == 0:
        issues.append(f'HIGH|{ref}|Pod securityContext runAsUser=0 (root)')

    for vol in (spec.get('volumes') or []):
        hp = vol.get('hostPath', {})
        if hp:
            path = hp.get('path','?')
            sev  = 'CRITICAL' if path.rstrip('/') in DANGEROUS_HOST_PATHS else 'HIGH'
            issues.append(f'{sev}|{ref}|hostPath volume "{path}" mounted')

    all_c = (spec.get('containers') or []) + \
            (spec.get('initContainers') or []) + \
            (spec.get('ephemeralContainers') or [])

    for c in all_c:
        cname = c.get('name','?')
        sc    = c.get('securityContext', {})
        cref  = f'{ref}/{cname}'

        if sc.get('privileged'):
            issues.append(f'CRITICAL|{cref}|privileged=true')
        if sc.get('allowPrivilegeEscalation') is not False and not sc.get('privileged'):
            issues.append(f'HIGH|{cref}|allowPrivilegeEscalation not explicitly false')
        if sc.get('runAsUser') == 0 or sc.get('runAsRoot'):
            issues.append(f'HIGH|{cref}|running as root (UID 0)')
        if not sc.get('readOnlyRootFilesystem'):
            issues.append(f'HIGH|{cref}|readOnlyRootFilesystem not enabled')

        caps_add = (sc.get('capabilities') or {}).get('add', [])
        for cap in caps_add:
            if cap.upper() in DANGEROUS_CAPS:
                issues.append(f'CRITICAL|{cref}|dangerous capability added: {cap}')

        img = c.get('image','')
        tag = img.split(':')[-1] if ':' in img.split('/')[-1] else 'latest'
        if tag in ('latest','') or ':' not in img.split('/')[-1]:
            issues.append(f'HIGH|{cref}|mutable/untagged image (image: {img})')

        ok += 1

for i in issues:
    print(i)
if not issues:
    print(f'PASS|cluster|All {ok} containers passed workload security checks')
PYEOF
  # shellcheck disable=SC2034
  local _dummy
  kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
DANGEROUS_CAPS = {'SYS_ADMIN','NET_ADMIN','SYS_PTRACE','SYS_MODULE','DAC_OVERRIDE','DAC_READ_SEARCH','SYS_RAWIO','SYS_BOOT','SYS_NICE','MKNOD','ALL'}
DANGEROUS_HOST_PATHS = {'/','/etc','/root','/proc','/sys','/var/run/docker.sock','/var/run/crio.sock','/run/containerd','/var/lib/kubelet'}
data = json.load(sys.stdin)
issues = []
ok = 0
for pod in data.get('items', []):
    meta = pod.get('metadata', {}); name = meta.get('name','?'); ns = meta.get('namespace','?'); spec = pod.get('spec', {}); ref = f'{ns}/{name}'
    if spec.get('hostNetwork'): issues.append(f'HIGH|{ref}|hostNetwork=true (bypasses NetworkPolicy)')
    if spec.get('hostPID'):     issues.append(f'HIGH|{ref}|hostPID=true (can inspect host processes)')
    if spec.get('hostIPC'):     issues.append(f'HIGH|{ref}|hostIPC=true (shared IPC namespace)')
    psc = spec.get('securityContext', {})
    if psc.get('runAsUser') == 0: issues.append(f'HIGH|{ref}|Pod securityContext runAsUser=0 (root)')
    for vol in (spec.get('volumes') or []):
        hp = vol.get('hostPath', {})
        if hp:
            path = hp.get('path','?'); sev = 'CRITICAL' if path.rstrip('/') in DANGEROUS_HOST_PATHS else 'HIGH'; issues.append(f'{sev}|{ref}|hostPath volume \"{path}\" mounted')
    all_c = (spec.get('containers') or []) + (spec.get('initContainers') or []) + (spec.get('ephemeralContainers') or [])
    for c in all_c:
        cname = c.get('name','?'); sc = c.get('securityContext', {}); cref = f'{ref}/{cname}'
        if sc.get('privileged'): issues.append(f'CRITICAL|{cref}|privileged=true')
        if sc.get('allowPrivilegeEscalation') is not False and not sc.get('privileged'): issues.append(f'HIGH|{cref}|allowPrivilegeEscalation not explicitly false')
        if sc.get('runAsUser') == 0 or sc.get('runAsRoot'): issues.append(f'HIGH|{cref}|running as root (UID 0)')
        if not sc.get('readOnlyRootFilesystem'): issues.append(f'HIGH|{cref}|readOnlyRootFilesystem not enabled')
        caps_add = (sc.get('capabilities') or {}).get('add', [])
        for cap in caps_add:
            if cap.upper() in DANGEROUS_CAPS: issues.append(f'CRITICAL|{cref}|dangerous capability added: {cap}')
        img = c.get('image',''); tag = img.split(':')[-1] if ':' in img.split('/')[-1] else 'latest'
        if tag in ('latest','') or ':' not in img.split('/')[-1]: issues.append(f'HIGH|{cref}|mutable/untagged image (image: {img})')
        ok += 1
for i in issues: print(i)
if not issues: print(f'PASS|cluster|All {ok} containers passed workload security checks')
" | while IFS='|' read -r sev loc msg; do
    case "$sev" in
      CRITICAL) critical "$loc — $msg" ;;
      HIGH)     high     "$loc — $msg" ;;
      PASS)     pass     "$msg" ;;
    esac
  done
}

# =============================================================================
# 3. NETWORK POLICIES
# =============================================================================
check_network_policies() {
  section "3/9 · Network Policy Coverage"

  log "Checking namespaces for missing NetworkPolicies..."
  local all_ns covered any_missing=false
  all_ns=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  covered=$(kubectl get networkpolicies $NS_FLAG \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}' 2>/dev/null | sort -u)

  for ns in $all_ns; do
    case "$ns" in kube-system|kube-public|kube-node-lease|gatekeeper-system) continue ;; esac
    if ! echo "$covered" | grep -qx "$ns"; then
      any_missing=true
      high "Namespace \"$ns\" has no NetworkPolicy — unrestricted east-west traffic"
    fi
  done
  [[ "$any_missing" == false ]] && pass "All scoped namespaces have at least one NetworkPolicy"

  log "Checking for default-deny NetworkPolicies..."
  local deny_found
  deny_found=$(kubectl get networkpolicies $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
ns_deny = set()
for np in data.get('items', []):
    ns   = np.get('metadata',{}).get('namespace','')
    spec = np.get('spec', {})
    sel  = spec.get('podSelector', {})
    ingress = spec.get('ingress'); egress = spec.get('egress')
    if sel == {} and (ingress is None or ingress == []) and (egress is None or egress == []):
        ns_deny.add(ns)
for ns in sorted(ns_deny): print(ns)
")
  for ns in $all_ns; do
    case "$ns" in kube-system|kube-public|kube-node-lease|gatekeeper-system) continue ;; esac
    if ! echo "$deny_found" | grep -qx "$ns"; then
      high "Namespace \"$ns\" lacks a default-deny NetworkPolicy (implicit allow-all)"
    fi
  done
}

# =============================================================================
# 4. SECRETS EXPOSURE
# =============================================================================
check_secrets_exposure() {
  section "4/9 · Secrets & Sensitive Data Exposure"

  log "Checking for Kubernetes Secrets injected as plain env vars..."
  local _env
  _env=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    for c in (pod.get('spec',{}).get('containers') or []):
        for env in (c.get('env') or []):
            vf = env.get('valueFrom', {})
            if 'secretKeyRef' in vf:
                sname = vf['secretKeyRef'].get('name','?'); key = vf['secretKeyRef'].get('key','?')
                print(f'HIGH|{ns}/{name}/{c[\"name\"]}|secret \"{sname}\" key \"{key}\" exposed as env var')
                found = True
if not found: print('PASS||No Secrets exposed directly as environment variables')
")
  echo "$_env" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done

  log "Checking for auto-mounted ServiceAccount tokens on default SA..."
  local _token
  _token=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    spec = pod.get('spec', {}); sa = spec.get('serviceAccountName','default'); amt = spec.get('automountServiceAccountToken', None)
    if sa == 'default' and amt is not False:
        print(f'HIGH|{ns}/{name}|default ServiceAccount token auto-mounted (unnecessary API access)')
        found = True
if not found: print('PASS||No pods using default SA with auto-mounted tokens')
")
  echo "$_token" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done

  log "Scanning ConfigMaps for likely embedded secrets (heuristic)..."
  local _cm
  _cm=$(kubectl get configmaps $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
patterns = [
    (re.compile(r'(?i)(password|passwd|secret|token|apikey|api_key|private.?key)\s*[:=]\s*\S+'), 'password/secret pattern'),
    (re.compile(r'(?i)BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY'), 'PEM private key block'),
]
found = False
for cm in data.get('items', []):
    ns = cm.get('metadata',{}).get('namespace','?'); name = cm.get('metadata',{}).get('name','?')
    if any(name.startswith(p) for p in ('kube-','azure-','omsagent','coredns','extension-')): continue
    for key, val in (cm.get('data') or {}).items():
        for pat, label in patterns:
            if pat.search(str(val)):
                print(f'HIGH|{ns}/{name}|key \"{key}\" matches {label} — use K8s Secret or Azure Key Vault')
                found = True; break
if not found: print('PASS||No obvious secrets detected in ConfigMaps')
")
  echo "$_cm" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done

  log "Checking for hardcoded secret-like values in pod env vars (literal)..."
  local _lit
  _lit=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
secret_keys = re.compile(r'(?i)(password|passwd|secret|token|apikey|api_key|connstr|connectionstring|sas_key)')
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    for c in (pod.get('spec',{}).get('containers') or []):
        for env in (c.get('env') or []):
            ename = env.get('name',''); val = env.get('value','')
            if secret_keys.search(ename) and val and 'valueFrom' not in env:
                print(f'CRITICAL|{ns}/{name}/{c[\"name\"]}|env var \"{ename}\" appears to contain a hardcoded secret')
                found = True
if not found: print('PASS||No hardcoded secret-like literal env vars detected')
")
  echo "$_lit" | while IFS='|' read -r sev ref msg; do
    case "$sev" in CRITICAL) critical "$ref — $msg";; PASS) pass "$msg";; esac
  done
}

# =============================================================================
# 5. AKS / AZURE-SPECIFIC CHECKS
# =============================================================================
check_aks_specific() {
  section "5/9 · AKS & Azure-Specific Checks"

  log "Checking ServiceAccounts for Workload Identity vs token auto-mount..."
  local _wi
  _wi=$(kubectl get serviceaccounts $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for sa in data.get('items', []):
    ns = sa.get('metadata',{}).get('namespace','?'); name = sa.get('metadata',{}).get('name','?')
    anns = sa.get('metadata',{}).get('annotations', {})
    if 'azure.workload.identity/client-id' in anns:
        print(f'PASS|{ns}/{name} uses Workload Identity (federated, secretless)')
    elif name != 'default':
        amt = sa.get('automountServiceAccountToken', True)
        if amt is not False:
            print(f'HIGH|{ns}/{name}|SA has no Workload Identity annotation and auto-mounts token')
")
  echo "$_wi" | while IFS='|' read -r sev msg; do
    case "$sev" in PASS) pass "$msg";; HIGH) high "$msg";; esac
  done

  log "Checking for legacy AAD Pod Identity (aadpodidbinding)..."
  local _podid
  _podid=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    labs = pod.get('metadata',{}).get('labels', {})
    if 'aadpodidbinding' in labs:
        print(f'HIGH|{ns}/{name}|uses legacy AAD Pod Identity \"{labs[\"aadpodidbinding\"]}\" — migrate to Workload Identity')
        found = True
if not found: print('PASS|No legacy AAD Pod Identity bindings found')
")
  echo "$_podid" | while IFS='|' read -r sev msg; do
    case "$sev" in HIGH) high "$msg";; PASS) pass "$msg";; esac
  done

  log "Checking workloads using raw K8s Secret volumes (vs AKV CSI)..."
  local _akv
  _akv=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    spec = pod.get('spec', {})
    uses_csi     = any(vol.get('csi', {}).get('driver','') == 'secrets-store.csi.k8s.io' for vol in (spec.get('volumes') or []))
    uses_secrets = any('secret' in vol for vol in (spec.get('volumes') or []))
    if uses_secrets and not uses_csi:
        print(f'HIGH|{ns}/{name}|mounts raw K8s Secret volume — consider Azure Key Vault CSI for rotation')
        found = True
if not found: print('PASS|All secret volumes use AKV CSI driver or no secret volumes present')
")
  echo "$_akv" | while IFS='|' read -r sev msg; do
    case "$sev" in HIGH) high "$msg";; PASS) pass "$msg";; esac
  done

  log "Checking for spot node pools without PodDisruptionBudgets..."
  local spot_nodes
  spot_nodes=$(kubectl get nodes -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for n in data.get('items', []):
    if n.get('metadata',{}).get('labels',{}).get('kubernetes.azure.com/scalesetpriority') == 'spot':
        print(n.get('metadata',{}).get('name','?'))
")
  if [[ -n "$spot_nodes" ]]; then
    local pdb_count
    pdb_count=$(kubectl get poddisruptionbudgets $NS_FLAG --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$pdb_count" -eq 0 ]]; then
      high "Spot node pool detected but no PodDisruptionBudgets found — workloads risk abrupt eviction"
    else
      pass "Spot nodes present and $pdb_count PodDisruptionBudget(s) configured"
    fi
  else
    pass "No spot node pools detected"
  fi

  log "Checking hostNetwork pods for Azure IMDS (169.254.169.254) access risk..."
  local _imds
  _imds=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    if pod.get('spec',{}).get('hostNetwork'):
        print(f'CRITICAL|{ns}/{name}|hostNetwork pod can reach Azure IMDS (169.254.169.254) and steal node identity')
        found = True
if not found: print('PASS|No hostNetwork pods that could access Azure IMDS')
")
  echo "$_imds" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      CRITICAL) critical "$ref — $msg" ;;
      PASS)     pass "$msg" ;;
    esac
  done

  log "Checking for OPA Gatekeeper / Azure Policy admission control..."
  if kubectl get namespace gatekeeper-system &>/dev/null 2>&1; then
    pass "OPA Gatekeeper (gatekeeper-system) is present"
    local ct_count
    ct_count=$(kubectl get constrainttemplate --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$ct_count" -eq 0 ]]; then
      high "Gatekeeper installed but no ConstraintTemplates found — policies may not be enforced"
    else
      pass "$ct_count ConstraintTemplate(s) found — admission policies active"
    fi
  else
    high "OPA Gatekeeper / Azure Policy for AKS not detected — no admission control enforcement"
  fi
}

# =============================================================================
# 6. API SERVER (AKS-observable)
# =============================================================================
check_api_server() {
  section "6/9 · API Server & Control Plane Settings"

  log "Testing anonymous access to the API server..."
  local anon_check
  anon_check=$(kubectl --as=system:anonymous get namespaces --no-headers 2>&1 || true)
  if echo "$anon_check" | grep -qiE "forbidden|unauthorized"; then
    pass "Anonymous authentication is disabled"
  else
    critical "API server may allow anonymous access — response: $(echo "$anon_check" | head -1)"
  fi

  log "Verifying unauthenticated users cannot list pods..."
  local can_i_result
  can_i_result=$(kubectl auth can-i list pods --as=system:unauthenticated 2>/dev/null || echo "no")
  if [[ "$can_i_result" == "yes" ]]; then
    critical "Unauthenticated users can list pods — RBAC may not be enforced"
  else
    pass "RBAC enforced — unauthenticated users cannot list pods"
  fi

  log "Checking for Pod Security Admission labels on namespaces..."
  local _psa
  _psa=$(kubectl get namespaces -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
skip = {'kube-system','kube-public','kube-node-lease','gatekeeper-system'}
for ns in data.get('items', []):
    name = ns.get('metadata',{}).get('name','')
    labs = ns.get('metadata',{}).get('labels', {})
    if name in skip: continue
    if any('pod-security' in k for k in labs):
        print(f'PASS|Namespace \"{name}\" has Pod Security Admission labels')
    else:
        print(f'HIGH|Namespace \"{name}\" has no Pod Security Admission labels')
")
  echo "$_psa" | while IFS='|' read -r sev msg; do
    case "$sev" in HIGH) high "$msg";; PASS) pass "$msg";; esac
  done

  log "Checking for exposed Kubernetes Dashboard..."
  local _dash
  _dash=$(kubectl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for svc in data.get('items', []):
    name = svc.get('metadata',{}).get('name',''); ns = svc.get('metadata',{}).get('namespace','')
    t = svc.get('spec',{}).get('type','')
    if 'dashboard' in name.lower():
        if t in ('LoadBalancer','NodePort'):
            print(f'CRITICAL|{ns}/{name}|Dashboard exposed via {t} — publicly reachable')
        else:
            print(f'HIGH|{ns}/{name}|Dashboard service exists (type {t}) — verify not externally reachable')
        found = True
if not found: print('PASS|No Kubernetes Dashboard service detected')
")
  echo "$_dash" | while IFS='|' read -r sev ref msg; do
    case "$sev" in CRITICAL) critical "$ref — $msg";; HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done
}

# =============================================================================
# 7. NODE SECURITY
# =============================================================================
check_nodes() {
  section "7/9 · Node Security Posture"

  log "Inspecting node health and configurations..."
  local _nodes
  _nodes=$(kubectl get nodes -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
issues = 0
for node in data.get('items', []):
    name  = node.get('metadata',{}).get('name','?')
    conds = node.get('status',{}).get('conditions', [])
    for cond in conds:
        t = cond.get('type','')
        if t == 'Ready' and cond.get('status') != 'True':
            print(f'HIGH|{name}|Node NOT Ready: {cond.get(\"reason\",\"unknown\")}')
            issues += 1
        if t in ('MemoryPressure','DiskPressure','PIDPressure') and cond.get('status') == 'True':
            print(f'HIGH|{name}|Node condition {t}=True — resource exhaustion risk')
            issues += 1
    if node.get('spec',{}).get('unschedulable'):
        print(f'HIGH|{name}|Node is cordoned (unschedulable) — may indicate stuck maintenance')
        issues += 1
if issues == 0:
    print('PASS|All nodes are Ready with no pressure conditions')
")
  echo "$_nodes" | while IFS='|' read -r sev node msg; do
    case "$sev" in HIGH) high "Node $node — $msg";; PASS) pass "$node";; esac
  done

  log "Checking for overly broad tolerations (tolerate all taints)..."
  local _tol
  _tol=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    for tol in (pod.get('spec',{}).get('tolerations') or []):
        if tol.get('operator') == 'Exists' and not tol.get('key'):
            print(f'HIGH|{ns}/{name}|tolerates ALL taints — can be scheduled on system/master nodes')
            found = True; break
if not found: print('PASS|No pods with catch-all tolerations found')
")
  echo "$_tol" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done
}

# =============================================================================
# 8. INGRESS & EXTERNAL EXPOSURE
# =============================================================================
check_ingress() {
  section "8/9 · Ingress & External Exposure"

  log "Checking for Services with public LoadBalancer IPs..."
  local _lb
  _lb=$(kubectl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
PRIVATE = ('10.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.',
           '172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.',
           '172.31.','192.168.')
found = False
for svc in data.get('items', []):
    ns = svc.get('metadata',{}).get('namespace','?'); name = svc.get('metadata',{}).get('name','?')
    if svc.get('spec',{}).get('type') != 'LoadBalancer': continue
    for ing in (svc.get('status',{}).get('loadBalancer',{}).get('ingress') or []):
        ip = ing.get('ip','')
        if not ip: continue
        ports = [str(p.get('port','?')) for p in (svc.get('spec',{}).get('ports') or [])]
        if any(ip.startswith(p) for p in PRIVATE):
            print(f'PASS|{ns}/{name}|Internal LoadBalancer IP {ip} (private)')
        else:
            print(f'HIGH|{ns}/{name}|Public IP {ip} on port(s) {\" \".join(ports)} — verify NSG/firewall')
        found = True
if not found: print('PASS|No LoadBalancer services with assigned IPs found')
")
  echo "$_lb" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$ref — $msg";; esac
  done

  log "Checking Ingress resources for missing TLS..."
  local _tls
  _tls=$(kubectl get ingress $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for ing in data.get('items', []):
    ns = ing.get('metadata',{}).get('namespace','?'); name = ing.get('metadata',{}).get('name','?')
    spec = ing.get('spec', {})
    if not spec.get('tls'):
        hosts = [r.get('host','?') for r in (spec.get('rules') or [])]
        print(f'HIGH|{ns}/{name}|No TLS configured (hosts: {\" \".join(hosts)})')
        found = True
if not found: print('PASS|All Ingress resources have TLS configured')
")
  echo "$_tls" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done

  log "Checking for NodePort services..."
  local _np
  _np=$(kubectl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for svc in data.get('items', []):
    ns = svc.get('metadata',{}).get('namespace','?'); name = svc.get('metadata',{}).get('name','?')
    if svc.get('spec',{}).get('type') == 'NodePort':
        ports = [str(p.get('nodePort','?')) for p in (svc.get('spec',{}).get('ports') or [])]
        print(f'HIGH|{ns}/{name}|NodePort service exposes node port(s) {\" \".join(ports)} — verify NSG rules')
        found = True
if not found: print('PASS|No NodePort services found')
")
  echo "$_np" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done
}

# =============================================================================
# 9. LEAST PRIVILEGE & MISCELLANEOUS
# =============================================================================
check_least_privilege() {
  section "9/9 · Least Privilege & Miscellaneous"

  log "Checking for ClusterRoles with dangerous pod verbs (exec/attach/portforward)..."
  local _exec
  _exec=$(kubectl get clusterroles -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
dangerous = {'exec','portforward','attach','proxy'}
found = False
for cr in data.get('items', []):
    name = cr.get('metadata',{}).get('name','')
    if name.startswith('system:'): continue
    for rule in (cr.get('rules') or []):
        overlap = dangerous & set(rule.get('verbs', []))
        if overlap and 'pods' in rule.get('resources', []):
            print(f'HIGH|{name}|grants dangerous pod verbs ({\" \".join(overlap)}) — risk of container breakout')
            found = True; break
if not found: print('PASS|No non-system ClusterRoles with dangerous pod exec verbs')
")
  echo "$_exec" | while IFS='|' read -r sev role msg; do
    case "$sev" in HIGH) high "ClusterRole \"$role\" — $msg";; PASS) pass "$msg";; esac
  done

  log "Checking for containers without resource limits (DoS risk)..."
  local _limits
  _limits=$(kubectl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    for c in (pod.get('spec',{}).get('containers') or []):
        if not c.get('resources', {}).get('limits'):
            print(f'HIGH|{ns}/{name}/{c[\"name\"]}|no resource limits set (CPU/memory exhaustion risk)')
            found = True
if not found: print('PASS|All containers have resource limits defined')
")
  echo "$_limits" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done

  log "Checking namespaces for LimitRange / ResourceQuota coverage..."
  local all_ns
  all_ns=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  local quota_issues=false
  for ns in $all_ns; do
    case "$ns" in kube-system|kube-public|kube-node-lease|gatekeeper-system) continue ;; esac
    local lr rq
    lr=$(kubectl get limitrange -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
    rq=$(kubectl get resourcequota -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$lr" -eq 0 && "$rq" -eq 0 ]]; then
      quota_issues=true
      high "Namespace \"$ns\" has no LimitRange or ResourceQuota — resource exhaustion risk"
    fi
  done
  [[ "$quota_issues" == false ]] && pass "All namespaces have LimitRange or ResourceQuota"

  log "Checking for deprecated API versions in use..."
  local _dep
  _dep=$(kubectl get ingresses,horizontalpodautoscalers,poddisruptionbudgets $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
deprecated = {'extensions/v1beta1','apps/v1beta1','apps/v1beta2','policy/v1beta1','networking.k8s.io/v1beta1','autoscaling/v2beta1'}
found = False
for item in data.get('items', []):
    av = item.get('apiVersion',''); ns = item.get('metadata',{}).get('namespace','?'); nm = item.get('metadata',{}).get('name','?')
    if av in deprecated:
        print(f'HIGH|{ns}/{nm}|uses deprecated API version \"{av}\" — may break on AKS upgrade')
        found = True
if not found: print('PASS|No resources using known deprecated API versions')
")
  echo "$_dep" | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$msg";; esac
  done
}

# =============================================================================
# SUMMARY
# =============================================================================
print_summary() {
  local total=$((CRITICAL_COUNT + HIGH_COUNT))
  echo ""
  echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${BLUE}║              SCAN COMPLETE — SUMMARY                ║${RESET}"
  echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${RESET}"
  printf "${BOLD}${BLUE}║${RESET}  %-28s %-24s${BOLD}${BLUE}║${RESET}\n" "Context:" "$(kubectl config current-context 2>/dev/null | cut -c1-24)"
  printf "${BOLD}${BLUE}║${RESET}  %-28s %-24s${BOLD}${BLUE}║${RESET}\n" "Scope:" "$NS_LABEL"
  printf "${BOLD}${BLUE}║${RESET}  %-28s %-24s${BOLD}${BLUE}║${RESET}\n" "Timestamp:" "$(date -u '+%Y-%m-%d %H:%M UTC')"
  echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════╣${RESET}"
  printf "${BOLD}${BLUE}║${RESET}  ${RED}${BOLD}%-28s %-24s${RESET}${BOLD}${BLUE}║${RESET}\n" "CRITICAL findings:" "$CRITICAL_COUNT"
  printf "${BOLD}${BLUE}║${RESET}  ${ORANGE}${BOLD}%-28s %-24s${RESET}${BOLD}${BLUE}║${RESET}\n" "HIGH findings:" "$HIGH_COUNT"
  printf "${BOLD}${BLUE}║${RESET}  ${GREEN}%-28s %-24s${RESET}${BOLD}${BLUE}║${RESET}\n" "Passed checks:" "$PASS_COUNT"
  printf "${BOLD}${BLUE}║${RESET}  %-28s %-24s${BOLD}${BLUE}║${RESET}\n" "Total issues:" "$total"
  echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${RESET}"

  if [[ $total -eq 0 ]]; then
    echo -e "\n${GREEN}${BOLD}  ✔ No critical or high findings detected. Great posture!${RESET}"
  fi

  if [[ -n "$OUTPUT_FILE" ]]; then
    {
      printf "Kubernetes Vulnerability Scan Report\n"
      printf "=====================================\n"
      printf "Context   : %s\n" "$(kubectl config current-context 2>/dev/null)"
      printf "Scope     : %s\n" "$NS_LABEL"
      printf "Date      : %s\n" "$(date -u)"
      printf "\nCRITICAL : %s\n" "$CRITICAL_COUNT"
      printf "HIGH     : %s\n" "$HIGH_COUNT"
      printf "PASSED   : %s\n" "$PASS_COUNT"
      printf "\nFindings\n--------\n"
      for f in "${FINDINGS[@]}"; do printf "%s\n" "$f"; done
    } > "$OUTPUT_FILE"
    echo -e "\n${CYAN}Report saved → $OUTPUT_FILE${RESET}"
  fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
  echo -e "${BOLD}${CYAN}"
  echo "  ╔═══════════════════════════════════════════════════════╗"
  echo "  ║     AKS VULNERABILITY SCANNER  —  kubectl native     ║"
  echo "  ║       Critical & High Severity Findings Only          ║"
  echo "  ╚═══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"

  preflight

  check_rbac
  check_privileged_workloads
  check_network_policies
  check_secrets_exposure
  check_aks_specific
  check_api_server
  check_nodes
  check_ingress
  check_least_privilege

  print_summary
}

main "$@"
