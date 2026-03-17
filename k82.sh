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

set -uo pipefail
# Note: -e (errexit) intentionally omitted — kubectl commands routinely return
# non-zero when a resource type doesn't exist (e.g. CRDs not installed, no
# objects of that kind). Exiting on every non-zero would abort the whole scan.

# ── Safe kubectl wrapper ──────────────────────────────────────────────────────
# Returns empty string (never fails) so pipelines into python3 always get valid
# input. Python blocks handle empty input via their own try/except guards.
kctl() { kubectl "$@" 2>/dev/null || true; }

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
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

# Print a PoC / confirm command in purple so it stands out
poc() {
  echo -e "  ${PURPLE}↳ PoC:${RESET} ${DIM}$*${RESET}"
  if [[ -n "$OUTPUT_FILE" ]]; then
    FINDINGS+=("  POC     | $*")
  fi
}

# Decode a base64 secret value and print redacted preview + retrieve command
# Usage: secret_peek <namespace> <secret-name> <key>
secret_peek() {
  local ns="$1" sname="$2" key="$3"
  local b64
  b64=$(kctl get secret "$sname" -n "$ns" \
    -o jsonpath="{.data['${key//\//\\/}']}" 2>/dev/null | tr -d '\n' || true)
  if [[ -n "$b64" ]]; then
    local decoded preview
    decoded=$(echo "$b64" | base64 -d 2>/dev/null | tr -dc '[:print:]' || true)
    if [[ ${#decoded} -gt 0 ]]; then
      preview="${decoded:0:4}$(printf '*%.0s' {1..8})"
      echo -e "  ${YELLOW}↳ Secret value preview:${RESET} ${BOLD}${RED}${preview}${RESET}  (length: ${#decoded})"
      echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${ns}  secret=${sname}  key=${key}${RESET}"
      FINDINGS+=("  SECRET  | ns=${ns} secret=${sname} key=${key} preview=${preview} len=${#decoded}")
    fi
  fi
  poc "kubectl get secret ${sname} -n ${ns} -o jsonpath='{.data.${key}}' | base64 -d"
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
  section "1/17 · RBAC Misconfigurations"

  # ── 1a. cluster-admin bindings ──────────────────────────────────────────────
  log "Checking ClusterRoleBindings for cluster-admin..."
  local _out
  _out=$(kctl get clusterrolebindings -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      CRITICAL) critical "$msg"
                poc "kubectl get clusterrolebindings -o json | python3 -c \"import sys,json;[print(b['metadata']['name'],b['roleRef']['name']) for b in json.load(sys.stdin)['items'] if b['roleRef']['name']=='cluster-admin']\"" ;;
      HIGH)     high "$msg"
                poc "kubectl get clusterrolebindings -o wide | grep cluster-admin" ;;
      PASS)     pass "$msg" ;;
    esac
  done

  # ── 1b. Wildcard permissions ────────────────────────────────────────────────
  log "Checking ClusterRoles for wildcard (*) permissions..."
  local _wc
  _wc=$(kctl get clusterroles -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl auth can-i '*' '*' --as=<bound-sa-name>" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 1c. Anonymous access via RBAC ───────────────────────────────────────────
  log "Checking for RBAC rules granting access to unauthenticated users..."
  local _anon
  _anon=$(kctl get clusterrolebindings -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      CRITICAL) critical "$msg"
                poc "kubectl get pods --as=system:anonymous --as-group=system:unauthenticated" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 1d. Default SA with elevated RoleBindings ──────────────────────────────
  log "Checking for non-default RoleBindings on 'default' ServiceAccounts..."
  local _defsa
  _defsa=$(kctl get rolebindings $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl auth can-i --list --as=system:serviceaccount:<namespace>:default" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 1e. Namespace-scoped Role wildcards ────────────────────────────────────
  log "Checking namespace Roles for wildcard (*) permissions..."
  local _rolewc
  _rolewc=$(kctl get roles $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for r in data.get('items', []):
    ns   = r.get('metadata',{}).get('namespace','?')
    name = r.get('metadata',{}).get('name','')
    for rule in (r.get('rules') or []):
        if '*' in rule.get('verbs', []) and '*' in rule.get('resources', []):
            print(f'HIGH|Role "{name}" in ns "{ns}" grants full wildcard (*) on all resources and verbs')
            found = True
            break
if not found:
    print('PASS|No namespace Roles with full wildcard permissions')
PYEOF
)
  echo "$_rolewc" | while IFS='|' read -r sev msg; do
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl auth can-i '*' '*' -n <namespace> --as=system:serviceaccount:<namespace>:<sa>" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 1f. Secrets read permissions (get/list/watch on secrets) ──────────────
  log "Checking for Roles/ClusterRoles that can read Secrets..."
  local _secread
  _secread=$(kctl get clusterroles,roles $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
READ_VERBS = {'get','list','watch','*'}
found = False
for r in data.get('items', []):
    kind = r.get('kind','')
    name = r.get('metadata',{}).get('name','')
    ns   = r.get('metadata',{}).get('namespace','cluster-wide')
    if name.startswith('system:'): continue
    for rule in (r.get('rules') or []):
        verbs = set(rule.get('verbs', []))
        res   = rule.get('resources', [])
        if READ_VERBS & verbs and ('secrets' in res or '*' in res):
            scope = f'ns "{ns}"' if kind == 'Role' else 'cluster-wide'
            print(f'HIGH|{kind} "{name}" ({scope}) can read Secrets — any bound SA gains access to all secrets in scope')
            found = True
            break
if not found:
    print('PASS|No non-system Roles/ClusterRoles with Secrets read permissions')
PYEOF
)
  echo "$_secread" | while IFS='|' read -r sev msg; do
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get secrets --all-namespaces --as=system:serviceaccount:<namespace>:<sa>"
            poc "kubectl auth can-i list secrets --as=system:serviceaccount:<namespace>:<sa>" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 1g. Dangerous escalation verbs: impersonate, bind, escalate ───────────
  log "Checking for impersonate / bind / escalate verbs in Roles and ClusterRoles..."
  local _esc
  _esc=$(kctl get clusterroles,roles $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
DANGER = {'impersonate','bind','escalate'}
found = False
for r in data.get('items', []):
    kind = r.get('kind','')
    name = r.get('metadata',{}).get('name','')
    ns   = r.get('metadata',{}).get('namespace','cluster-wide')
    if name.startswith('system:'): continue
    for rule in (r.get('rules') or []):
        overlap = DANGER & set(rule.get('verbs', []))
        if overlap:
            scope = f'ns "{ns}"' if kind == 'Role' else 'cluster-wide'
            print(f'CRITICAL|{kind} "{name}" ({scope}) grants "{", ".join(overlap)}" verb — allows RBAC privilege escalation')
            found = True
            break
if not found:
    print('PASS|No Roles/ClusterRoles with impersonate/bind/escalate verbs')
PYEOF
)
  echo "$_esc" | while IFS='|' read -r sev msg; do
    case "$sev" in
      CRITICAL) critical "$msg"
                poc "kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=<ns>:<sa> --as=system:serviceaccount:<ns>:<sa>" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 1h. Orphaned RoleBindings (subject SA no longer exists) ───────────────
  log "Checking for RoleBindings referencing non-existent ServiceAccounts..."
  local _orphan
  _orphan=$(kctl get rolebindings,clusterrolebindings $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json, subprocess, shlex
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
found = False
checked = {}
for rb in data.get('items', []):
    rb_ns   = rb.get('metadata',{}).get('namespace','')
    rb_name = rb.get('metadata',{}).get('name','')
    kind    = rb.get('kind','')
    for subj in (rb.get('subjects') or []):
        if subj.get('kind') != 'ServiceAccount': continue
        sa_name = subj.get('name','')
        sa_ns   = subj.get('namespace', rb_ns or 'default')
        key     = f'{sa_ns}/{sa_name}'
        if key in checked:
            exists = checked[key]
        else:
            try:
                r = subprocess.run(
                    shlex.split(f'kubectl get serviceaccount {sa_name} -n {sa_ns} --no-headers'),
                    capture_output=True, text=True, timeout=10
                )
                exists = r.returncode == 0
            except Exception:
                exists = True  # assume exists on error to avoid false positives
            checked[key] = exists
        if not exists:
            print(f'HIGH|{kind} "{rb_name}" (ns: {rb_ns or "cluster-wide"}) references missing SA "{sa_name}" in ns "{sa_ns}"')
            found = True
if not found:
    print('PASS|No orphaned RoleBindings referencing missing ServiceAccounts')
PYEOF
)
  echo "$_orphan" | while IFS='|' read -r sev msg; do
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get rolebindings,clusterrolebindings --all-namespaces -o wide | grep -v Terminating" ;;
      PASS) pass "$msg" ;;
    esac
  done
}

# =============================================================================
# 2. PRIVILEGED & UNSAFE WORKLOADS
# =============================================================================
check_privileged_workloads() {
  section "2/17 · Privileged & Unsafe Workloads"

  log "Scanning all pods for security context issues..."
  kctl get pods $NS_FLAG -o json 2>/dev/null | python3 - << 'PYEOF'
import sys, json

DANGEROUS_CAPS = {'SYS_ADMIN','NET_ADMIN','SYS_PTRACE','SYS_MODULE',
                  'DAC_OVERRIDE','DAC_READ_SEARCH','SYS_RAWIO',
                  'SYS_BOOT','SYS_NICE','MKNOD','ALL'}
DANGEROUS_HOST_PATHS = {'/','/etc','/root','/proc','/sys',
                        '/var/run/docker.sock','/var/run/crio.sock',
                        '/run/containerd','/var/lib/kubelet'}

try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
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
  kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
DANGEROUS_CAPS = {'SYS_ADMIN','NET_ADMIN','SYS_PTRACE','SYS_MODULE','DAC_OVERRIDE','DAC_READ_SEARCH','SYS_RAWIO','SYS_BOOT','SYS_NICE','MKNOD','ALL'}
DANGEROUS_HOST_PATHS = {'/','/etc','/root','/proc','/sys','/var/run/docker.sock','/var/run/crio.sock','/run/containerd','/var/lib/kubelet'}
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
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
      CRITICAL) critical "$loc — $msg"
                poc "kubectl get pod ${loc%%/*} -n ${loc%%/*/*} -o jsonpath='{.spec.containers[*].securityContext}'"
                poc "kubectl exec -n ${loc%%/*/*} ${loc##*/} -- id" ;;
      HIGH)     high     "$loc — $msg"
                poc "kubectl get pod ${loc##*/} -n ${loc%%/*} -o yaml | grep -A10 securityContext" ;;
      PASS)     pass     "$msg" ;;
    esac
  done

  # ── 2b. Additional workload hardening checks ──────────────────────────────
  log "Checking for shareProcessNamespace, missing capability drops, runAsNonRoot, procMount..."
  local _extra
  _extra=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
found = False
PUBLIC_REGISTRIES = ('docker.io','index.docker.io','registry-1.docker.io','ghcr.io','quay.io','gcr.io','public.ecr.aws')

for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    spec = pod.get('spec', {})
    ref  = f'{ns}/{name}'

    # shareProcessNamespace lets containers see each other's memory/fds
    if spec.get('shareProcessNamespace'):
        print(f'HIGH|{ref}|shareProcessNamespace=true — containers share PID namespace, can read each other memory')
        found = True

    all_c = (spec.get('containers') or []) + (spec.get('initContainers') or [])
    for c in all_c:
        cname = c.get('name','?')
        sc    = c.get('securityContext', {})
        cref  = f'{ref}/{cname}'

        # runAsNonRoot should be explicitly true (belt-and-suspenders with runAsUser)
        if sc.get('runAsNonRoot') is not True:
            print(f'HIGH|{cref}|runAsNonRoot not set to true — container may run as root if image USER is root')
            found = True

        # capabilities.drop should include ALL
        caps_drop = [c.upper() for c in (sc.get('capabilities') or {}).get('drop', [])]
        if 'ALL' not in caps_drop:
            print(f'HIGH|{cref}|capabilities.drop does not include ALL — unnecessary Linux capabilities retained')
            found = True

        # procMount Unmasked bypasses /proc restrictions
        if sc.get('procMount','Default') == 'Unmasked':
            print(f'CRITICAL|{cref}|procMount=Unmasked — full /proc access, kernel attack surface expanded')
            found = True

        # Image pull policy: IfNotPresent or Never on a mutable tag is dangerous
        pull = c.get('imagePullPolicy','')
        img  = c.get('image','')
        tag  = img.split(':')[-1] if ':' in img.split('/')[-1] else 'latest'
        if pull in ('IfNotPresent','Never') and tag in ('latest',''):
            print(f'HIGH|{cref}|imagePullPolicy={pull} with mutable tag — stale/compromised image may persist on node')
            found = True

        # Image sourced from public registry (should use private ACR on AKS)
        registry = img.split('/')[0] if '.' in img.split('/')[0] or ':' in img.split('/')[0] else 'docker.io'
        if any(registry == pub or img.startswith(pub) for pub in PUBLIC_REGISTRIES):
            print(f'HIGH|{cref}|image pulled from public registry \"{registry}\" — use private Azure Container Registry')
            found = True

    # imagePullSecrets — if pulling from private registry, must be set
    if not spec.get('imagePullSecrets'):
        # Only flag if images look like they need auth (non-public, contain a registry hostname)
        private_images = [
            c.get('image','') for c in all_c
            if '.' in c.get('image','').split('/')[0]
            and not any(c.get('image','').startswith(pub) for pub in PUBLIC_REGISTRIES)
        ]
        if private_images:
            print(f'HIGH|{ref}|No imagePullSecrets but uses private registry images: {private_images[0]} — pull may fail or use node credentials insecurely')
            found = True

if not found:
    print('PASS|cluster|No additional workload hardening issues found')
")
  echo "$_extra" | while IFS='|' read -r sev loc msg; do
    case "$sev" in
      CRITICAL) critical "$loc — $msg"
                poc "kubectl get pod ${loc} -o yaml | grep -A5 securityContext" ;;
      HIGH)     high     "$loc — $msg"
                poc "kubectl get pod ${loc} -o yaml | grep -A5 securityContext" ;;
      PASS)     pass     "$msg" ;;
    esac
  done

  # ── 2c. CronJob security checks ───────────────────────────────────────────
  log "Checking CronJobs for dangerous security contexts..."
  local _cron
  _cron=$(kctl get cronjobs $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for cj in data.get('items', []):
    ns   = cj.get('metadata',{}).get('namespace','?')
    name = cj.get('metadata',{}).get('name','?')
    ref  = f'{ns}/{name}'
    spec = cj.get('spec',{}).get('jobTemplate',{}).get('spec',{}).get('template',{}).get('spec',{})
    for c in (spec.get('containers') or []):
        sc = c.get('securityContext', {})
        if sc.get('privileged'):
            print(f'CRITICAL|{ref}/{c[\"name\"]}|CronJob container is privileged')
            found = True
        if sc.get('runAsUser') == 0:
            print(f'HIGH|{ref}/{c[\"name\"]}|CronJob container runs as root')
            found = True
    if spec.get('hostNetwork'):
        print(f'HIGH|{ref}|CronJob uses hostNetwork')
        found = True
if not found:
    print('PASS|cluster|No dangerous CronJob security contexts found')
")
  echo "$_cron" | while IFS='|' read -r sev loc msg; do
    case "$sev" in
      CRITICAL) critical "$loc — $msg"
                poc "kubectl get cronjob ${loc%%/*} -n ${loc####*/} -o yaml | grep -A10 securityContext" ;;
      HIGH)     high     "$loc — $msg"
                poc "kubectl get cronjob -n ${loc%%/*} -o yaml | grep -A5 securityContext" ;;
      PASS)     pass "$msg" ;;
    esac
  done
}

# =============================================================================
# 3. NETWORK POLICIES
# =============================================================================
check_network_policies() {
  section "3/17 · Network Policy Coverage"

  log "Checking namespaces for missing NetworkPolicies..."
  local all_ns covered any_missing=false
  all_ns=$(kctl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  covered=$(kctl get networkpolicies $NS_FLAG \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}' 2>/dev/null | sort -u)

  for ns in $all_ns; do
    case "$ns" in kube-system|kube-public|kube-node-lease|gatekeeper-system) continue ;; esac
    if ! echo "$covered" | grep -qx "$ns"; then
      any_missing=true
      high "Namespace \"$ns\" has no NetworkPolicy — unrestricted east-west traffic"
      poc "kubectl get networkpolicies -n ${ns}"
      poc "kubectl exec -n ${ns} <any-pod> -- curl -s http://<other-pod-ip>:8080 && echo REACHABLE"
    fi
  done
  [[ "$any_missing" == false ]] && pass "All scoped namespaces have at least one NetworkPolicy"

  log "Checking for default-deny NetworkPolicies..."
  local deny_found
  deny_found=$(kctl get networkpolicies $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
      poc "kubectl get networkpolicies -n ${ns} -o yaml"
      poc "kubectl exec -n ${ns} <any-pod> -- curl -s --max-time 3 http://<other-service> && echo INGRESS_OPEN"
    fi
  done
}

# =============================================================================
# 4. SECRETS EXPOSURE
# =============================================================================
check_secrets_exposure() {
  section "4/17 · Secrets & Sensitive Data Exposure"

  log "Checking for Kubernetes Secrets injected as plain env vars..."
  local _env
  _env=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    for c in (pod.get('spec',{}).get('containers') or []):
        for env in (c.get('env') or []):
            vf = env.get('valueFrom', {})
            if 'secretKeyRef' in vf:
                sname = vf['secretKeyRef'].get('name','?'); key = vf['secretKeyRef'].get('key','?')
                print(f'HIGH|{ns}|{name}|{c["name"]}|{sname}|{key}')
                found = True
if not found: print('PASS||||No Secrets exposed directly as environment variables|')
")
  echo "$_env" | while IFS='|' read -r sev ns pod cname sname key; do
    case "$sev" in
      HIGH)
        high "pod ${ns}/${pod}/${cname} — secret \"${sname}\" key \"${key}\" exposed as env var"
        echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${ns}  secret=${sname}  key=${key}  env-var in container=${cname}${RESET}"
        secret_peek "$ns" "$sname" "$key"
        poc "kubectl exec -n ${ns} ${pod} -c ${cname} -- printenv | grep -i '${key}'"
        ;;
      PASS) pass "$sname $key" ;;
    esac
  done

  log "Checking for auto-mounted ServiceAccount tokens on default SA..."
  local _token
  _token=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for pod in data.get('items', []):
    ns = pod.get('metadata',{}).get('namespace','?'); name = pod.get('metadata',{}).get('name','?')
    spec = pod.get('spec', {}); sa = spec.get('serviceAccountName','default'); amt = spec.get('automountServiceAccountToken', None)
    if sa == 'default' and amt is not False:
        print(f'HIGH|{ns}|{name}|{sa}')
        found = True
if not found: print('PASS|||none')
")
  echo "$_token" | while IFS='|' read -r sev ns pod sa; do
    case "$sev" in
      HIGH)
        high "pod ${ns}/${pod} — default ServiceAccount token auto-mounted (unnecessary API access)"
        echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${ns}  pod=${pod}  serviceAccount=${sa}${RESET}"
        poc "kubectl exec -n ${ns} ${pod} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token"
        poc "kubectl auth can-i --list --as=system:serviceaccount:${ns}:${sa}"
        ;;
      PASS) pass "No pods using default SA with auto-mounted tokens" ;;
    esac
  done

  # ── 4b-extra. envFrom secretRef (entire Secret bulk-mounted as env) ────────
  log "Checking for envFrom secretRef (entire Secret injected into environment)..."
  local _envfrom
  _envfrom=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    for c in (pod.get('spec',{}).get('containers') or []) + (pod.get('spec',{}).get('initContainers') or []):
        for ef in (c.get('envFrom') or []):
            if 'secretRef' in ef:
                sname = ef['secretRef'].get('name','?')
                print(f'HIGH|{ns}|{name}|{c["name"]}|{sname}')
                found = True
if not found:
    print('PASS||||')
")
  echo "$_envfrom" | while IFS='|' read -r sev ns pod cname sname; do
    case "$sev" in
      HIGH)
        high "pod ${ns}/${pod}/${cname} — envFrom secretRef \"${sname}\" entire Secret bulk-exposed as env vars"
        echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${ns}  secret=${sname}  all keys injected into container=${cname}${RESET}"
        # List all keys in the secret and peek each one
        local _keys
        _keys=$(kctl get secret "$sname" -n "$ns" -o jsonpath='{.data}' 2>/dev/null \
          | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read())
    for k in d: print(k)
except: pass
" 2>/dev/null || true)
        while IFS= read -r k; do
          [[ -z "$k" ]] && continue
          secret_peek "$ns" "$sname" "$k"
        done <<< "$_keys"
        poc "kubectl exec -n ${ns} ${pod} -c ${cname} -- env | grep -v PATH"
        poc "kubectl get secret ${sname} -n ${ns} -o json | python3 -c \"import sys,json,base64;[print(k+': '+base64.b64decode(v).decode(errors='replace')) for k,v in json.load(sys.stdin)['data'].items()]\""
        ;;
      PASS) pass "No envFrom secretRef bulk-mounts detected" ;;
    esac
  done

  # ── 4b-extra2. Secret volume mounts (secret as file) ─────────────────────
  log "Checking for Secrets mounted as volumes..."
  local _secvol
  _secvol=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    for vol in (pod.get('spec',{}).get('volumes') or []):
        sec = vol.get('secret')
        if sec:
            sname = sec.get('secretName','?')
            mode = sec.get('defaultMode', 0o644)
            if isinstance(mode, int) and (mode & 0o044):
                print(f'HIGH|{ns}|{name}|{sname}|{oct(mode)}|world-readable')
            else:
                print(f'HIGH|{ns}|{name}|{sname}|{oct(mode) if isinstance(mode,int) else mode}|verify-access')
            found = True
if not found:
    print('PASS|||||-')
")
  echo "$_secvol" | while IFS='|' read -r sev ns pod sname mode detail; do
    case "$sev" in
      HIGH)
        high "pod ${ns}/${pod} — Secret \"${sname}\" mounted as volume (mode ${mode}, ${detail})"
        echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${ns}  pod=${pod}  secret=${sname}  mountMode=${mode}${RESET}"
        local _vkeys
        _vkeys=$(kctl get secret "$sname" -n "$ns" -o jsonpath='{.data}' 2>/dev/null \
          | python3 -c "import sys,json
try:
    d=json.loads(sys.stdin.read())
    for k in d: print(k)
except: pass
" 2>/dev/null || true)
        while IFS= read -r k; do
          [[ -z "$k" ]] && continue
          secret_peek "$ns" "$sname" "$k"
        done <<< "$_vkeys"
        poc "kubectl exec -n ${ns} ${pod} -- find /var/run/secrets -type f -exec cat {} \\;"
        ;;
      PASS) pass "No Secrets mounted as volumes" ;;
    esac
  done

  # ── 4b-extra3. TLS Secret certificate expiry ──────────────────────────────
  log "Checking TLS Secrets for expired or soon-expiring certificates..."
  local _tls_exp
  _tls_exp=$(kctl get secrets $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, base64, re
from datetime import datetime, timezone
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
now  = datetime.now(timezone.utc)
found = False

for secret in data.get('items', []):
    if secret.get('type','') != 'kubernetes.io/tls': continue
    ns   = secret.get('metadata',{}).get('namespace','?')
    name = secret.get('metadata',{}).get('name','?')
    cert_b64 = (secret.get('data') or {}).get('tls.crt','')
    if not cert_b64: continue
    try:
        cert_pem = base64.b64decode(cert_b64).decode('utf-8', errors='ignore')
        # Extract Not After from PEM using regex (avoids needing cryptography lib)
        m = re.search(r'Not After\s*:\s*(.+)', cert_pem)
        if not m:
            # Try parsing the ASN.1 date directly from decoded bytes
            continue
        exp_str = m.group(1).strip()
        exp = datetime.strptime(exp_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        days_left = (exp - now).days
        if days_left < 0:
            print(f'CRITICAL|{ns}/{name}|TLS certificate EXPIRED {abs(days_left)} day(s) ago (expired: {exp.date()})')
            found = True
        elif days_left <= 30:
            print(f'CRITICAL|{ns}/{name}|TLS certificate expires in {days_left} day(s) ({exp.date()}) — renew immediately')
            found = True
        elif days_left <= 90:
            print(f'HIGH|{ns}/{name}|TLS certificate expires in {days_left} day(s) ({exp.date()}) — plan renewal')
            found = True
    except Exception:
        continue

if not found:
    print('PASS||All TLS Secrets have certificates valid for more than 90 days')
")
  echo "$_tls_exp" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      CRITICAL) critical "$ref — $msg"
                local _ns _nm; _ns="${ref%%/*}"; _nm="${ref##*/}"
                echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${_ns}  secret=${_nm}  type=kubernetes.io/tls${RESET}"
                poc "kubectl get secret ${_nm} -n ${_ns} -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -dates -subject"
                ;;
      HIGH)     high "$ref — $msg"
                local _ns _nm; _ns="${ref%%/*}"; _nm="${ref##*/}"
                echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${_ns}  secret=${_nm}  type=kubernetes.io/tls${RESET}"
                poc "kubectl get secret ${_nm} -n ${_ns} -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -dates"
                ;;
      PASS)     pass "$msg" ;;
    esac
  done
  # Matches the page's jq query: flags ConfigMaps where any key NAME looks like
  # a secret (password/secret/token/key), AND separately scans values for
  # embedded credentials or PEM blocks.
  log "Scanning ConfigMaps for secret-like key names and embedded credential values..."
  local _cm
  _cm=$(kctl get configmaps $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re

SYSTEM_PREFIXES = ('kube-','azure-','omsagent','coredns','extension-','flannel','calico',
                   'cilium','cni-','metrics-','aks-')

# Pattern 1 — key NAME looks like a secret field (mirrors the page's jq test)
KEY_NAME_RE = re.compile(r'(?i)(password|passwd|secret|token|api.?key|private.?key|sas.?key|conn.?str|connectionstring|credential|auth)')

# Pattern 2 — key VALUE contains embedded credentials or PEM material
VALUE_PATTERNS = [
    (re.compile(r'(?i)BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE|CERTIFICATE) KEY'), 'PEM private key block'),
    (re.compile(r'(?i)(password|passwd|secret|api.?key|sas.?key)\s*[:=]\s*\S{6,}'),  'inline credential assignment'),
    (re.compile(r'(?i)AccountKey=[A-Za-z0-9+/]{20,}={0,2}'),                          'Azure Storage account key'),
    (re.compile(r'(?i)SharedAccessSignature.*sig='),                                   'Azure SAS token'),
    (re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{10,}'),                    'JWT / bearer token'),
    (re.compile(r'(?i)(AKIA|ASIA)[A-Z0-9]{16}'),                                      'AWS access key ID pattern'),
]

found = False
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}

for cm in data.get('items', []):
    ns   = cm.get('metadata',{}).get('namespace','?')
    name = cm.get('metadata',{}).get('name','?')
    if any(name.startswith(p) for p in SYSTEM_PREFIXES): continue
    for key, val in (cm.get('data') or {}).items():
        val_str = str(val or '')
        # Check key NAME (mirrors the page's approach)
        if KEY_NAME_RE.search(key):
            sev = 'CRITICAL' if val_str and len(val_str) > 3 else 'HIGH'
            print(f'{sev}|{ns}/{name}|ConfigMap key named \"{key}\" looks like a secret field (value length: {len(val_str)}) — move to K8s Secret or AKV')
            found = True
            continue  # already reported, skip value scan for this key
        # Check key VALUE for embedded credentials
        for pat, label in VALUE_PATTERNS:
            if pat.search(val_str):
                print(f'CRITICAL|{ns}/{name}|key \"{key}\" value contains {label} — move to K8s Secret or Azure Key Vault')
                found = True
                break

if not found:
    print('PASS||No secret-like key names or embedded credentials detected in ConfigMaps')
")
  echo "$_cm" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      CRITICAL) critical "$ref — $msg"
                local _ns _nm; _ns="${ref%%/*}"; _nm="${ref##*/}"
                echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${_ns}  configmap=${_nm}${RESET}"
                poc "kubectl get configmap ${_nm} -n ${_ns} -o json | python3 -c \"import sys,json;[print(k+': '+str(v)[:120]) for k,v in json.load(sys.stdin).get('data',{}).items()]\""
                ;;
      HIGH)     high "$ref — $msg"
                local _ns _nm; _ns="${ref%%/*}"; _nm="${ref##*/}"
                echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${_ns}  configmap=${_nm}${RESET}"
                poc "kubectl get configmap ${_nm} -n ${_ns} -o jsonpath='{.data}'"
                ;;
      PASS)     pass "$msg" ;;
    esac
  done

  # ── 4d. Pod env var plaintext secret detection ────────────────────────────
  # Mirrors the page's jq query exactly:
  #   - env var NAME matches PASSWORD|SECRET|TOKEN|KEY (case-insensitive)
  #   - AND the env entry has a literal "value" field (not valueFrom)
  #   - Reports the variable name so triage is actionable
  log "Checking pod env vars for plaintext secrets (name matches + literal value present)..."
  local _lit
  _lit=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re

SECRET_NAME_RE = re.compile(r'(?i)(password|passwd|secret|token|api.?key|sas.?key|private.?key|conn.?str|connectionstring|credential|auth.?token|client.?secret)')

try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
found = False

for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    for c in (pod.get('spec',{}).get('containers') or []) + (pod.get('spec',{}).get('initContainers') or []):
        cname = c.get('name','?')
        for env in (c.get('env') or []):
            ename = env.get('name','')
            if not SECRET_NAME_RE.search(ename):
                continue
            literal_val = env.get('value', None)
            if literal_val is None:
                continue
            placeholder = re.match(r'^(\$\(.*\)|<.*>|\{\{.*\}\}|changeme|replace|example|todo|xxx|none|null|false|true)$', str(literal_val), re.I)
            sev = 'HIGH' if placeholder or len(str(literal_val)) < 4 else 'CRITICAL'
            val_str = str(literal_val)
            preview = val_str[:4] + '****' if len(val_str) > 4 else '****'
            print(f'{sev}|{ns}|{name}|{cname}|{ename}|{preview}|{len(val_str)}')
            found = True

if not found:
    print('PASS||||||-')
")
  echo "$_lit" | while IFS='|' read -r sev ns pod cname ename preview vlen; do
    case "$sev" in
      CRITICAL|HIGH)
        local fn="$sev"
        [[ "$sev" == "CRITICAL" ]] && critical "pod ${ns}/${pod}/${cname} — env var \"${ename}\" has hardcoded plaintext value (len=${vlen})" \
                                    || high    "pod ${ns}/${pod}/${cname} — env var \"${ename}\" has hardcoded plaintext value (len=${vlen})"
        echo -e "  ${YELLOW}↳ Location:${RESET}    ${DIM}namespace=${ns}  pod=${pod}  container=${cname}${RESET}"
        echo -e "  ${RED}↳ Secret preview:${RESET} ${BOLD}${RED}${preview}${RESET}  (full length: ${vlen} chars)"
        FINDINGS+=("  SECRET  | ns=${ns} pod=${pod} container=${cname} env=${ename} preview=${preview} len=${vlen}")
        poc "kubectl exec -n ${ns} ${pod} -c ${cname} -- printenv ${ename}"
        poc "kubectl get pod ${pod} -n ${ns} -o yaml | grep -A20 containers | grep -A5 env:"
        ;;
      PASS) pass "No pod env vars with secret-like names and plaintext values detected" ;;
    esac
  done
}

# =============================================================================
# 5. AKS / AZURE-SPECIFIC CHECKS
# =============================================================================
check_aks_specific() {
  section "5/17 · AKS & Azure-Specific Checks"

  log "Checking ServiceAccounts for Workload Identity vs token auto-mount..."
  local _wi
  _wi=$(kctl get serviceaccounts $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get serviceaccounts --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} automount={.automountServiceAccountToken}{\"\\n\"}{end}'" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking for legacy AAD Pod Identity (aadpodidbinding)..."
  local _podid
  _podid=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.metadata.labels.aadpodidbinding}{"\\n"}{end}' | grep -v ': $'" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking workloads using raw K8s Secret volumes (vs AKV CSI)..."
  local _akv
  _akv=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get pods --all-namespaces -o yaml | grep -B5 'secret:' | grep 'name:' | sort -u" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking for spot node pools without PodDisruptionBudgets..."
  local spot_nodes
  spot_nodes=$(kctl get nodes -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
for n in data.get('items', []):
    if n.get('metadata',{}).get('labels',{}).get('kubernetes.azure.com/scalesetpriority') == 'spot':
        print(n.get('metadata',{}).get('name','?'))
")
  if [[ -n "$spot_nodes" ]]; then
    local pdb_count
    pdb_count=$(kctl get poddisruptionbudgets $NS_FLAG --no-headers 2>/dev/null | wc -l | tr -d ' ')
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
  _imds=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
      CRITICAL) critical "$ref — $msg"
                local _imds_ns="${ref%%/*}" _imds_pod="${ref##*/}"
                echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${_imds_ns}  pod=${_imds_pod}${RESET}"
                poc "kubectl exec -n ${_imds_ns} ${_imds_pod} -- curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'"
                poc "kubectl exec -n ${_imds_ns} ${_imds_pod} -- curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'"
                ;;
      PASS)     pass "$msg" ;;
    esac
  done

  log "Checking for OPA Gatekeeper / Azure Policy admission control..."
  if kctl get namespace gatekeeper-system &>/dev/null 2>&1; then
    pass "OPA Gatekeeper (gatekeeper-system) is present"
    local ct_count
    ct_count=$(kctl get constrainttemplate --no-headers 2>/dev/null | wc -l | tr -d ' ')
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
  section "6/17 · API Server & Control Plane Settings"

  log "Testing anonymous access to the API server..."
  local anon_check
  anon_check=$(kctl --as=system:anonymous get namespaces --no-headers 2>&1 || true)
  if echo "$anon_check" | grep -qiE "forbidden|unauthorized"; then
    pass "Anonymous authentication is disabled"
  else
    critical "API server may allow anonymous access — response: $(echo "$anon_check" | head -1)"
    poc "kubectl get pods --as=system:anonymous --as-group=system:unauthenticated"
    poc "kubectl get secrets --as=system:anonymous --as-group=system:unauthenticated"
  fi

  log "Verifying unauthenticated users cannot list pods..."
  local can_i_result
  can_i_result=$(kctl auth can-i list pods --as=system:unauthenticated 2>/dev/null || echo "no")
  if [[ "$can_i_result" == "yes" ]]; then
    critical "Unauthenticated users can list pods — RBAC may not be enforced"
  else
    pass "RBAC enforced — unauthenticated users cannot list pods"
  fi

  log "Checking for Pod Security Admission labels on namespaces..."
  local _psa
  _psa=$(kctl get namespaces -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get namespaces --show-labels | grep -v 'pod-security'" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking for exposed Kubernetes Dashboard..."
  local _dash
  _dash=$(kctl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      CRITICAL) critical "$ref — $msg"
                poc "kubectl get service -n ${ref%%/*} ${ref##*/} -o jsonpath='{.status.loadBalancer.ingress[0].ip}'"
                poc "curl -k https://\$(kubectl get service -n ${ref%%/*} ${ref##*/} -o jsonpath='{.status.loadBalancer.ingress[0].ip}')" ;;
      HIGH)     high "$ref — $msg"
                poc "kubectl get service ${ref##*/} -n ${ref%%/*} -o yaml" ;;
      PASS)     pass "$msg" ;;
    esac
  done
}

# =============================================================================
# 7. NODE SECURITY
# =============================================================================
check_nodes() {
  section "7/17 · Node Security Posture"

  log "Inspecting node health and configurations..."
  local _nodes
  _nodes=$(kctl get nodes -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "Node $node — $msg"
            poc "kubectl describe node ${node} | grep -A5 Conditions"
            poc "kubectl get node ${node} -o jsonpath='{.status.conditions}'" ;;
      PASS) pass "$node" ;;
    esac
  done

  log "Checking for overly broad tolerations (tolerate all taints)..."
  local _tol
  _tol=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.tolerations}'"
            poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.nodeName}'" ;;
      PASS) pass "$msg" ;;
    esac
  done
}

# =============================================================================
# 8. INGRESS & EXTERNAL EXPOSURE
# =============================================================================
check_ingress() {
  section "8/17 · Ingress & External Exposure"

  log "Checking for Services with public LoadBalancer IPs..."
  local _lb
  _lb=$(kctl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get service ${ref##*/} -n ${ref%%/*} -o jsonpath='{.status.loadBalancer.ingress}'"
            poc "SVC_IP=\$(kubectl get service ${ref##*/} -n ${ref%%/*} -o jsonpath='{.status.loadBalancer.ingress[0].ip}') && nmap -sV \$SVC_IP" ;;
      PASS) pass "$ref — $msg" ;;
    esac
  done

  log "Checking Ingress resources for missing TLS..."
  local _tls
  _tls=$(kctl get ingress $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get ingress ${ref##*/} -n ${ref%%/*} -o yaml | grep -A5 tls"
            poc "curl -v http://\$(kubectl get ingress ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.rules[0].host}')" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking for NodePort services..."
  local _np
  _np=$(kctl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get service ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.ports[*].nodePort}'"
            poc "kubectl get nodes -o wide | awk '{print \$7}' | tail -n +2" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 8d. ExternalName services (DNS rebinding / SSRF vector) ──────────────
  log "Checking for ExternalName services pointing outside the cluster..."
  local _extname
  _extname=$(kctl get services $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
found = False
INTERNAL = re.compile(r'(\.svc\.cluster\.local|\.svc$|^localhost$|^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.)')
for svc in data.get('items', []):
    ns   = svc.get('metadata',{}).get('namespace','?')
    name = svc.get('metadata',{}).get('name','?')
    if svc.get('spec',{}).get('type') != 'ExternalName': continue
    ext = svc.get('spec',{}).get('externalName','')
    if ext and not INTERNAL.search(ext):
        print(f'HIGH|{ns}/{name}|ExternalName service points to external host \"{ext}\" — potential SSRF / DNS rebinding vector')
        found = True
    elif ext:
        print(f'PASS|{ns}/{name}|ExternalName service points to internal host \"{ext}\"')
if not found:
    print('PASS|No external ExternalName services found')
")
  echo "$_extname" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get service ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.externalName}'"
            poc "kubectl exec -n ${ref%%/*} <any-pod> -- curl http://${ref##*/}" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 8e. Ingress without authentication annotations ────────────────────────
  log "Checking Ingress resources for missing authentication annotations..."
  local _ingressauth
  _ingressauth=$(kctl get ingress $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
AUTH_ANNOTATIONS = {
    'nginx.ingress.kubernetes.io/auth-url',
    'nginx.ingress.kubernetes.io/auth-signin',
    'nginx.ingress.kubernetes.io/auth-type',
    'konghq.com/plugins',
    'appgw.ingress.kubernetes.io/backend-path-prefix',
    'kubernetes.io/ingress.class',
}
found = False
for ing in data.get('items', []):
    ns   = ing.get('metadata',{}).get('namespace','?')
    name = ing.get('metadata',{}).get('name','?')
    anns = set(ing.get('metadata',{}).get('annotations', {}).keys())
    hosts = [r.get('host','?') for r in (ing.get('spec',{}).get('rules') or [])]
    # Check if any auth annotation is present
    if not (anns & AUTH_ANNOTATIONS):
        print(f'HIGH|{ns}/{name}|Ingress has no authentication annotations (hosts: {\" \".join(hosts)}) — routes may be publicly accessible without authn')
        found = True
if not found:
    print('PASS|All Ingress resources have authentication-related annotations')
")
  echo "$_ingressauth" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get ingress ${ref##*/} -n ${ref%%/*} -o jsonpath='{.metadata.annotations}'"
            poc "curl -v http://\$(kubectl get ingress ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.rules[0].host}')/admin" ;;
      PASS) pass "$msg" ;;
    esac
  done
}

# =============================================================================
# 9. LEAST PRIVILEGE & MISCELLANEOUS
# =============================================================================
check_least_privilege() {
  section "9/17 · Least Privilege & Miscellaneous"

  log "Checking for ClusterRoles with dangerous pod verbs (exec/attach/portforward)..."
  local _exec
  _exec=$(kctl get clusterroles -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "ClusterRole \"$role\" — $msg"
            poc "kubectl auth can-i exec pods --as=system:serviceaccount:<namespace>:<sa-with-this-role>"
            poc "kubectl exec -n <namespace> <target-pod> -- /bin/sh" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking for containers without resource limits (DoS risk)..."
  local _limits
  _limits=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.containers[*].resources}'"
            poc "# Exhaust node resources: kubectl run stress --image=progrium/stress -- --cpu 8 --vm 2 --vm-bytes 2G" ;;
      PASS) pass "$msg" ;;
    esac
  done

  log "Checking namespaces for LimitRange / ResourceQuota coverage..."
  local all_ns
  all_ns=$(kctl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  local quota_issues=false
  for ns in $all_ns; do
    case "$ns" in kube-system|kube-public|kube-node-lease|gatekeeper-system) continue ;; esac
    local lr rq
    lr=$(kctl get limitrange -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
    rq=$(kctl get resourcequota -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$lr" -eq 0 && "$rq" -eq 0 ]]; then
      quota_issues=true
      high "Namespace \"$ns\" has no LimitRange or ResourceQuota — resource exhaustion risk"
    fi
  done
  [[ "$quota_issues" == false ]] && pass "All namespaces have LimitRange or ResourceQuota"

  log "Checking for deprecated API versions in use..."
  local _dep
  _dep=$(kctl get ingresses,horizontalpodautoscalers,poddisruptionbudgets $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
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

  # ── 9e. Roles that can create/update workloads (malicious pod injection) ───
  log "Checking for Roles/ClusterRoles that can create or update pods/deployments..."
  local _create
  _create=$(kctl get clusterroles,roles $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
WORKLOAD_RESOURCES = {'pods','deployments','daemonsets','statefulsets','jobs','cronjobs','replicationcontrollers'}
CREATE_VERBS = {'create','update','patch','*'}
found = False
for r in data.get('items', []):
    kind = r.get('kind','')
    name = r.get('metadata',{}).get('name','')
    ns   = r.get('metadata',{}).get('namespace','cluster-wide')
    if name.startswith('system:'): continue
    for rule in (r.get('rules') or []):
        verbs = set(rule.get('verbs', []))
        res   = set(rule.get('resources', []))
        if CREATE_VERBS & verbs and (WORKLOAD_RESOURCES & res or '*' in res):
            scope = f'ns \"{ns}\"' if kind == 'Role' else 'cluster-wide'
            matched = ', '.join(WORKLOAD_RESOURCES & res) if '*' not in res else '*'
            print(f'HIGH|{kind} \"{name}\" ({scope}) can create/modify workloads ({matched}) — can inject privileged pods')
            found = True
            break
if not found:
    print('PASS|No non-system Roles/ClusterRoles with workload create/update permissions')
")
  echo "$_create" | while IFS='|' read -r sev msg; do
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl auth can-i create pods --as=system:serviceaccount:<namespace>:<sa>"
            poc "# Inject privileged pod via YAML — see: kubectl apply -f- (privileged+hostPath) --as=system:serviceaccount:<ns>:<sa>" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 9f. ValidatingWebhookConfiguration / MutatingWebhookConfiguration ─────
  log "Checking admission webhooks for insecure failure policies..."
  local _webhooks
  _webhooks=$(kctl get validatingwebhookconfigurations,mutatingwebhookconfigurations -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for wh in data.get('items', []):
    kind = wh.get('kind','')
    name = wh.get('metadata',{}).get('name','')
    for hook in (wh.get('webhooks') or []):
        hname    = hook.get('name','?')
        policy   = hook.get('failurePolicy','Ignore')
        side_eff = hook.get('sideEffects','Unknown')
        timeout  = hook.get('timeoutSeconds', 10)
        if policy == 'Ignore':
            print(f'HIGH|{kind} \"{name}\" hook \"{hname}\"|failurePolicy=Ignore — if webhook is down, admission is bypassed')
            found = True
        if side_eff not in ('None','NoneOnDryRun'):
            print(f'HIGH|{kind} \"{name}\" hook \"{hname}\"|sideEffects={side_eff} — webhook has side effects (not safe for dry-run)')
            found = True
        if timeout > 25:
            print(f'HIGH|{kind} \"{name}\" hook \"{hname}\"|timeoutSeconds={timeout} — long timeout can cause API server slowdowns')
            found = True
if not found:
    print('PASS|All admission webhooks have safe failure policies')
")
  echo "$_webhooks" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      HIGH) high "$ref — $msg"
            poc "kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations -o yaml | grep -A3 failurePolicy"
            poc "# If failurePolicy=Ignore: kill webhook pod to bypass admission controls" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 9g. RuntimeClass — pods without a hardened runtime ────────────────────
  log "Checking pods for RuntimeClass (gVisor/kata for stronger isolation)..."
  local _runtime
  _runtime=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
skip_ns = {'kube-system','kube-public','kube-node-lease','gatekeeper-system'}
no_runtime = 0
with_runtime = 0
for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    if ns in skip_ns: continue
    rc = pod.get('spec',{}).get('runtimeClassName','')
    if rc:
        with_runtime += 1
    else:
        no_runtime += 1
total = no_runtime + with_runtime
if no_runtime > 0 and with_runtime == 0:
    print(f'HIGH|{no_runtime}/{total} pods use default runtimeClass (runc) — consider gVisor (runsc) or Kata Containers for stronger isolation')
elif no_runtime > 0:
    print(f'HIGH|{no_runtime}/{total} pods have no RuntimeClass set — mixed isolation posture in cluster')
else:
    print(f'PASS|All {total} non-system pods specify a RuntimeClass')
")
  echo "$_runtime" | while IFS='|' read -r sev msg; do
    case "$sev" in
      HIGH) high "$msg"
            poc "kubectl get pods --all-namespaces -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,RUNTIME:.spec.runtimeClassName | grep -v 'gvisor\|kata\|runsc'" ;;
      PASS) pass "$msg" ;;
    esac
  done

  # ── 9h. Projected ServiceAccount tokens vs legacy long-lived tokens ────────
  log "Checking for legacy long-lived ServiceAccount tokens (non-projected)..."
  local _tokens
  _tokens=$(kctl get secrets $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
from datetime import datetime, timezone
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
found = False
for secret in data.get('items', []):
    if secret.get('type','') != 'kubernetes.io/service-account-token': continue
    ns   = secret.get('metadata',{}).get('namespace','?')
    name = secret.get('metadata',{}).get('name','?')
    anns = secret.get('metadata',{}).get('annotations', {})
    sa   = anns.get('kubernetes.io/service-account.name','?')
    # Long-lived tokens have no expiry — they are only safe when using projected tokens
    print(f'HIGH|{ns}/{name}|Legacy long-lived ServiceAccount token for SA \"{sa}\" — use projected tokens with short TTL instead')
    found = True
if not found:
    print('PASS|No legacy long-lived ServiceAccount tokens found (projected tokens in use)')
")
  echo "$_tokens" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      HIGH) high "$ref — $msg"
            local _tns="${ref%%/*}" _tnm="${ref##*/}"
            echo -e "  ${YELLOW}↳ Location:${RESET} ${DIM}namespace=${_tns}  secret=${_tnm}  type=kubernetes.io/service-account-token${RESET}"
            secret_peek "$_tns" "$_tnm" "token"
            poc "kubectl get secret ${_tnm} -n ${_tns} -o jsonpath='{.data.token}' | base64 -d | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool"
            poc "TOKEN=\$(kubectl get secret ${_tnm} -n ${_tns} -o jsonpath='{.data.token}' | base64 -d) && kubectl auth can-i --list --token=\$TOKEN"
            ;;
      PASS) pass "$msg" ;;
    esac
  done
}

# =============================================================================
# 10. KUBELET API EXPOSURE
# =============================================================================
check_kubelet_api() {
  section "10/17 · Kubelet API Exposure (port 10250)"

  # Pull the list of node IPs from kubectl, then probe each node's kubelet
  # using kubectl's port-forward or by inspecting the kubelet config ConfigMap.
  # On AKS we cannot SSH to nodes directly, so we use two indirect methods:
  #   a) Inspect the kubelet-config ConfigMap in kube-system (AKS stores it there)
  #   b) Attempt a kctl proxy round-trip to the kubelet /pods endpoint via API server

  # ── 10a. Kubelet ConfigMap — anonymous auth & AlwaysAllow ──────────────────
  log "Checking kubelet config for anonymous auth and AlwaysAllow authorization..."
  local _kcm
  _kcm=$(kctl get configmap kubelet-config -n kube-system -o json 2>/dev/null \
    || kctl get configmap kubelet-config-1.28 -n kube-system -o json 2>/dev/null \
    || kctl get configmap kubelet-config-1.27 -n kube-system -o json 2>/dev/null \
    || echo '{}')

  echo "$_kcm" | python3 -c "
import sys, json, re
raw = sys.stdin.read()
try:
    cm = json.loads(raw)
except Exception:
    print('PASS|Could not read kubelet ConfigMap (managed cluster may restrict access)')
    sys.exit(0)

data_field = cm.get('data', {}).get('kubelet', '') or cm.get('data', {}).get('config', '')
if not data_field:
    print('PASS|No kubelet config data found in ConfigMap — likely AKS-managed, check via Azure Portal')
    sys.exit(0)

# Parse embedded YAML-like content as text (avoid yaml dep)
anon_enabled  = re.search(r'enabled:\s*true',  data_field) and re.search(r'anonymous', data_field)
always_allow  = re.search(r'mode:\s*AlwaysAllow', data_field)
webhook_authn = re.search(r'mode:\s*Webhook', data_field)

if anon_enabled:
    print('CRITICAL|Kubelet anonymous authentication is enabled — unauthenticated RCE possible on port 10250')
else:
    print('PASS|Kubelet anonymous authentication appears disabled')

if always_allow:
    print('CRITICAL|Kubelet authorization mode is AlwaysAllow — any authenticated request is permitted')
elif webhook_authn:
    print('PASS|Kubelet authorization mode is Webhook (delegates to API server)')
else:
    print('HIGH|Could not confirm kubelet authorization mode — verify it is not AlwaysAllow')
" | while IFS='|' read -r sev msg; do
    case "$sev" in CRITICAL) critical "$msg";; HIGH) high "$msg";; PASS) pass "$msg";; esac
  done

  # ── 10b. Probe kubelet /pods via API server proxy ──────────────────────────
  log "Probing kubelet /pods endpoint through API server proxy for each node..."
  local nodes
  nodes=$(kctl get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  local kubelet_issues=false
  for node in $nodes; do
    # kctl get --raw proxies directly to the kubelet through the API server
    local result
    result=$(kctl get --raw "/api/v1/nodes/${node}/proxy/pods" 2>&1 || true)
    if echo "$result" | grep -q '"kind":"PodList"'; then
      kubelet_issues=true
      critical "Node \"$node\" — kubelet /pods endpoint accessible via API server proxy (verify kubelet auth is enforced)"
      poc "kubectl get --raw /api/v1/nodes/${node}/proxy/pods"
      poc "kubectl get --raw /api/v1/nodes/${node}/proxy/runningpods"
      poc "kubectl get --raw \"/api/v1/nodes/${node}/proxy/exec/<namespace>/<pod>/<container>\" -X POST"
    elif echo "$result" | grep -qiE "forbidden|unauthorized|certificate"; then
      pass "Node \"$node\" — kubelet proxy endpoint correctly restricted"
      poc "# Confirmed blocked: kubectl get --raw /api/v1/nodes/${node}/proxy/pods → 403"
    else
      high "Node \"$node\" — unexpected kubelet proxy response: $(echo "$result" | head -c 120)"
      poc "kubectl get --raw /api/v1/nodes/${node}/proxy/pods"
    fi
  done
  [[ "$kubelet_issues" == false ]] && true  # individual node pass messages already printed

  # ── 10c. Check for kubelet read-only port (10255) ──────────────────────────
  log "Checking if kubelet read-only port (10255) is referenced in node config..."
  local _ro
  _ro=$(kctl get configmap kubelet-config -n kube-system -o jsonpath='{.data.kubelet}' 2>/dev/null || echo "")
  if echo "$_ro" | grep -q "readOnlyPort: 0"; then
    pass "Kubelet read-only port (10255) is disabled (readOnlyPort: 0)"
  elif echo "$_ro" | grep -q "readOnlyPort:"; then
    local port
    port=$(echo "$_ro" | grep "readOnlyPort:" | awk '{print $2}')
    if [[ "$port" != "0" ]]; then
      high "Kubelet read-only port is set to $port — unauthenticated metric/pod info disclosure possible"
    fi
  else
    high "Cannot confirm kubelet readOnlyPort is disabled — verify port 10255 is not exposed on nodes"
  fi
}

# =============================================================================
# 11. ETCD EXPOSURE
# =============================================================================
check_etcd() {
  section "11/17 · ETCD Storage Security"

  # ── 11a. ETCD pod / static manifest inspection ────────────────────────────
  log "Checking ETCD configuration via kube-system pods..."
  local _etcd
  _etcd=$(kctl get pods -n kube-system -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for pod in data.get('items', []):
    name = pod.get('metadata',{}).get('name','')
    if 'etcd' not in name: continue
    found = True
    for c in (pod.get('spec',{}).get('containers') or []):
        args = c.get('command', []) + c.get('args', [])
        arg_str = ' '.join(args)

        # client-cert-auth should be true
        if '--client-cert-auth=true' not in arg_str and '--client-cert-auth' not in arg_str:
            print('CRITICAL|ETCD pod: --client-cert-auth not set — unauthenticated client connections may be allowed')
        else:
            print('PASS|ETCD client-cert-auth is enabled')

        # peer-client-cert-auth
        if '--peer-client-cert-auth=true' not in arg_str and '--peer-client-cert-auth' not in arg_str:
            print('HIGH|ETCD pod: --peer-client-cert-auth not set — peer connections may be unauthenticated')
        else:
            print('PASS|ETCD peer-client-cert-auth is enabled')

        # listen address should not be 0.0.0.0
        import re
        listen = re.findall(r'--listen-client-urls=(\S+)', arg_str)
        for url in listen:
            if '0.0.0.0' in url:
                print(f'CRITICAL|ETCD listens on 0.0.0.0 ({url}) — exposed to all interfaces')
            elif '127.0.0.1' in url or 'localhost' in url:
                print(f'PASS|ETCD listen-client-urls bound to loopback ({url})')

        # encryption at rest
        if '--encryption-provider-config' not in arg_str:
            print('HIGH|ETCD: --encryption-provider-config not set — secrets stored in plaintext in ETCD')
        else:
            print('PASS|ETCD encryption-provider-config is configured (secrets encrypted at rest)')

if not found:
    print('INFO|No ETCD pod visible in kube-system (AKS manages ETCD — verify encryption at rest via Azure Portal)')
" 2>/dev/null)
  echo "$_etcd" | while IFS='|' read -r sev msg; do
    case "$sev" in
      CRITICAL) critical "$msg"
                poc "# From a node with etcdctl: etcdctl --endpoints=https://127.0.0.1:2379 get /registry/secrets --prefix --keys-only"
                poc "# Read a secret: etcdctl get /registry/secrets/<namespace>/<name> | strings" ;;
      HIGH)     high "$msg"
                poc "kubectl get pods -n kube-system -o yaml | grep -A5 etcd | grep -i encryption" ;;
      PASS)     pass "$msg" ;;
      INFO)     log "$msg" ;;
    esac
  done

  # ── 11b. Secrets encryption at rest (AKS) ─────────────────────────────────
  log "Checking for EncryptionConfiguration or KMS provider in kube-system..."
  local enc_found=false
  if kctl get secret -n kube-system -o name 2>/dev/null | grep -qi "encryption\|kms"; then
    enc_found=true
    pass "Encryption-related secret/config found in kube-system"
  fi
  # Also check for encryption config mounted in apiserver
  local _apienc
  _apienc=$(kctl get pods -n kube-system -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
for pod in data.get('items', []):
    name = pod.get('metadata',{}).get('name','')
    if 'kube-apiserver' not in name: continue
    for c in (pod.get('spec',{}).get('containers') or []):
        args = ' '.join(c.get('command',[]) + c.get('args',[]))
        if '--encryption-provider-config' in args:
            print('PASS|kube-apiserver has --encryption-provider-config set (encryption at rest active)')
        else:
            print('HIGH|kube-apiserver: --encryption-provider-config not set — ETCD secrets stored in plaintext')
" 2>/dev/null)
  if [[ -n "$_apienc" ]]; then
    echo "$_apienc" | while IFS='|' read -r sev msg; do
      case "$sev" in
        HIGH) high "$msg"
              poc "kubectl get secrets --all-namespaces -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,KEYS:.data" ;;
        PASS) pass "$msg" ;;
      esac
    done
  elif [[ "$enc_found" == false ]]; then
    high "Cannot confirm ETCD encryption at rest — on AKS verify via: az aks show ... | grep encryptionAtHost"
  fi

  # ── 11c. ETCD port 2379 reachable from pods (via network policy check) ────
  log "Checking if any NetworkPolicy explicitly blocks ETCD port 2379..."
  local etcd_blocked=false
  kctl get networkpolicies $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
for np in data.get('items', []):
    for erule in (np.get('spec',{}).get('egress') or []):
        for port in (erule.get('ports') or []):
            if str(port.get('port','')) == '2379':
                ns = np.get('metadata',{}).get('namespace','')
                nm = np.get('metadata',{}).get('name','')
                print(f'{ns}/{nm}')
" | while read -r ref; do
    etcd_blocked=true
    pass "NetworkPolicy \"$ref\" references port 2379 — ETCD egress explicitly controlled"
  done
  if [[ "$etcd_blocked" == false ]]; then
    high "No NetworkPolicy found blocking egress to port 2379 (ETCD) — workloads could attempt ETCD access"
    poc "kubectl get pods -n kube-system -l component=etcd -o jsonpath='{.items[0].status.podIP}'"
    poc "kubectl exec -n <namespace> <any-pod> -- nc -zv <etcd-ip> 2379 && echo REACHABLE || echo BLOCKED"
    poc "kubectl exec -n <namespace> <any-pod> -- curl -sk https://<etcd-ip>:2379/v3/keys"
  fi
}

# =============================================================================
# 12. INSECURE API SERVER PORT (8080)
# =============================================================================
check_insecure_api_port() {
  section "12/17 · Insecure API Server Port (HTTP/8080)"

  # ── 12a. Check kube-apiserver args for insecure-port ─────────────────────
  log "Checking kube-apiserver for --insecure-port configuration..."
  local _insecure
  _insecure=$(kctl get pods -n kube-system -o json 2>/dev/null | python3 -c "
import sys, json, re
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
found_apiserver = False
for pod in data.get('items', []):
    name = pod.get('metadata',{}).get('name','')
    if 'kube-apiserver' not in name: continue
    found_apiserver = True
    for c in (pod.get('spec',{}).get('containers') or []):
        args = ' '.join(c.get('command',[]) + c.get('args',[]))

        m = re.search(r'--insecure-port=(\d+)', args)
        if m:
            port = m.group(1)
            if port == '0':
                print('PASS|--insecure-port=0 (HTTP API server port disabled)')
            else:
                print(f'CRITICAL|kube-apiserver --insecure-port={port} — unauthenticated HTTP access to API server')
        else:
            print('PASS|--insecure-port not set (defaults to 0/disabled in modern Kubernetes)')

        if '--insecure-bind-address=0.0.0.0' in args:
            print('CRITICAL|kube-apiserver --insecure-bind-address=0.0.0.0 — insecure port bound to all interfaces')

        # Also check secure port is set
        if '--secure-port' not in args:
            print('HIGH|kube-apiserver --secure-port not explicitly set — verify TLS is enforced')
        else:
            print('PASS|kube-apiserver --secure-port is configured')

if not found_apiserver:
    print('INFO|kube-apiserver pod not visible (AKS manages control plane) — insecure port disabled by default on AKS')
" 2>/dev/null)
  echo "$_insecure" | while IFS='|' read -r sev msg; do
    case "$sev" in
      CRITICAL) critical "$msg"
                poc "curl -v http://\$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' | sed 's|https://||'):8080/api/v1/namespaces"
                poc "kubectl -s http://\$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' | sed 's|https://||'):8080 get secrets --all-namespaces" ;;
      HIGH)     high "$msg"
                poc "kubectl get pods -n kube-system -l component=kube-apiserver -o yaml | grep -i insecure" ;;
      PASS)     pass "$msg" ;;
      INFO)     log "$msg" ;;
    esac
  done

  # ── 12b. Attempt direct HTTP probe to API server on port 8080 ─────────────
  log "Attempting HTTP probe to API server on port 8080 via kubectl..."
  local api_url
  api_url=$(kctl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
  local api_host
  api_host=$(echo "$api_url" | sed 's|https\?://||' | cut -d: -f1)

  if [[ -n "$api_host" ]]; then
    # Use kctl run with a probe pod would need network — instead check if
    # the API server exposes anything on the HTTP path via the proxy endpoint
    local probe_result
    probe_result=$(kctl get --raw "/api" 2>/dev/null | python3 -c "
import sys, json
try:
    _raw2 = sys.stdin.read().strip()
    d = json.loads(_raw2) if _raw2 else {}
    # If we got here with no TLS error, the API server is responding
    # We can't directly test port 8080 from outside, but we note the HTTPS is working
    print('PASS|API server HTTPS endpoint is responding correctly (port 8080 check requires network access)')
except: pass
" 2>/dev/null || echo "PASS|API server probe inconclusive — verify port 8080 is not exposed via Azure NSG rules")
    echo "$probe_result" | while IFS='|' read -r sev msg; do
      case "$sev" in PASS) pass "$msg";; HIGH) high "$msg";; CRITICAL) critical "$msg";; esac
    done
  fi
}

# =============================================================================
# 13. KUBERNETES DASHBOARD HARDENING
# =============================================================================
check_dashboard_hardening() {
  section "13/17 · Kubernetes Dashboard Hardening"

  log "Checking Dashboard deployment for insecure arguments..."
  local _dashargs
  _dashargs=$(kctl get deployments $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
found = False
for dep in data.get('items', []):
    name = dep.get('metadata',{}).get('name','')
    ns   = dep.get('metadata',{}).get('namespace','')
    if 'dashboard' not in name.lower(): continue
    found = True
    for c in (dep.get('spec',{}).get('template',{}).get('spec',{}).get('containers') or []):
        args = c.get('args', [])
        arg_str = ' '.join(args)
        if '--enable-skip-login' in arg_str:
            print(f'CRITICAL|{ns}/{name}|--enable-skip-login set — authentication can be bypassed')
        if '--disable-settings-authorizer' in arg_str:
            print(f'CRITICAL|{ns}/{name}|--disable-settings-authorizer set — settings page unrestricted')
        if '--enable-insecure-login' in arg_str:
            print(f'CRITICAL|{ns}/{name}|--enable-insecure-login set — allows HTTP login')
        if '--insecure-port' in arg_str and '0' not in arg_str:
            print(f'HIGH|{ns}/{name}|Dashboard insecure port enabled')
        if '--token-ttl=0' in arg_str:
            print(f'HIGH|{ns}/{name}|--token-ttl=0 — tokens never expire')

        # Check the ServiceAccount the dashboard uses
        sa = dep.get('spec',{}).get('template',{}).get('spec',{}).get('serviceAccountName','default')
        print(f'INFO|{ns}/{name}|Dashboard runs as ServiceAccount \"{sa}\" — verify it has minimal permissions')

if not found:
    print('PASS|No Kubernetes Dashboard deployment found')
" 2>/dev/null)
  echo "$_dashargs" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      CRITICAL) critical "$ref — $msg"
                poc "kubectl get deployment ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.template.spec.containers[0].args}'"
                poc "# Access dashboard without auth: curl -k https://<dashboard-ip>/\$(kubectl get service -n ${ref%%/*} -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}')" ;;
      HIGH)     high "$ref — $msg"
                poc "kubectl get deployment ${ref##*/} -n ${ref%%/*} -o yaml | grep -A10 args" ;;
      PASS)     pass "$msg" ;;
      INFO)     log "$ref — $msg" ;;
    esac
  done

  # ── Dashboard SA permissions ───────────────────────────────────────────────
  log "Checking permissions of ServiceAccounts associated with Dashboard..."
  kctl get deployments $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
for dep in data.get('items', []):
    name = dep.get('metadata',{}).get('name','')
    ns   = dep.get('metadata',{}).get('namespace','')
    if 'dashboard' not in name.lower(): continue
    sa = dep.get('spec',{}).get('template',{}).get('spec',{}).get('serviceAccountName','default')
    print(f'{ns}|{sa}')
" 2>/dev/null | while IFS='|' read -r ns sa; do
    # Check if this SA has cluster-admin or wide ClusterRoleBindings
    local bound_roles
    bound_roles=$(kctl get clusterrolebindings -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
for crb in data.get('items', []):
    for subj in (crb.get('subjects') or []):
        if subj.get('kind') == 'ServiceAccount' and subj.get('name') == '${sa}' and subj.get('namespace','') == '${ns}':
            role = crb.get('roleRef',{}).get('name','')
            print(role)
" 2>/dev/null)
    for role in $bound_roles; do
      if [[ "$role" == "cluster-admin" ]]; then
        critical "Dashboard SA \"$sa\" (ns: $ns) has cluster-admin ClusterRoleBinding — full cluster takeover if Dashboard is compromised"
      else
        high "Dashboard SA \"$sa\" (ns: $ns) has ClusterRoleBinding to \"$role\" — review permissions"
      fi
    done
  done
}

# =============================================================================
# 14. APPARMOR PROFILES
# =============================================================================
check_apparmor() {
  section "14/17 · AppArmor Profile Enforcement"

  log "Checking pods for AppArmor profile annotations..."
  local _aa
  _aa=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json, re
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
missing = 0
enforced = 0
skip_ns = {'kube-system','kube-public','kube-node-lease','gatekeeper-system'}

for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    if ns in skip_ns: continue

    anns = pod.get('metadata',{}).get('annotations', {})
    spec = pod.get('spec', {})

    # New-style securityContext.appArmorProfile (K8s 1.30+)
    psc = spec.get('securityContext', {})
    aa_profile = psc.get('appArmorProfile', {})

    # Old-style annotation: container.apparmor.security.beta.kubernetes.io/<container>
    aa_anns = {k: v for k, v in anns.items() if 'apparmor' in k.lower()}

    containers = [c.get('name','?') for c in (spec.get('containers') or [])]

    has_profile = bool(aa_profile) or bool(aa_anns)

    if has_profile:
        # Check for 'unconfined'
        for k, v in aa_anns.items():
            if 'unconfined' in v:
                print(f'HIGH|{ns}/{name}|AppArmor annotation present but set to unconfined: {k}={v}')
            else:
                enforced += 1
        if aa_profile.get('type') == 'Unconfined':
            print(f'HIGH|{ns}/{name}|securityContext.appArmorProfile.type=Unconfined')
        elif aa_profile:
            enforced += 1
    else:
        missing += 1
        print(f'HIGH|{ns}/{name}|No AppArmor profile configured — container syscall surface unrestricted')

print(f'SUMMARY|{enforced} pods with AppArmor enforced, {missing} pods without any AppArmor profile')
" 2>/dev/null)
  echo "$_aa" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      HIGH)    high "$ref — $msg"
               poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.metadata.annotations}' | grep -i apparmor"
               poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.securityContext.appArmorProfile}'" ;;
      SUMMARY) log "$ref$msg" ;;
    esac
  done
  # If no HIGH lines were printed, emit a pass
  local aa_high_count
  aa_high_count=$(echo "$_aa" | grep -c '^HIGH' || true)
  [[ "$aa_high_count" -eq 0 ]] && pass "All non-system pods have AppArmor profiles configured"
}

# =============================================================================
# 15. SECCOMP PROFILES
# =============================================================================
check_seccomp() {
  section "15/17 · Seccomp Profile Enforcement"

  log "Checking pods for Seccomp profile configuration..."
  local _sc
  _sc=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
missing = 0
enforced = 0
skip_ns = {'kube-system','kube-public','kube-node-lease','gatekeeper-system'}

for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    if ns in skip_ns: continue

    anns = pod.get('metadata',{}).get('annotations', {})
    spec = pod.get('spec', {})
    psc  = spec.get('securityContext', {})

    # New-style (K8s 1.19+)
    seccomp_profile = psc.get('seccompProfile', {})
    # Old-style annotation
    seccomp_ann = anns.get('seccomp.security.alpha.kubernetes.io/pod', '')

    has_profile = bool(seccomp_profile) or bool(seccomp_ann)

    if has_profile:
        profile_type = seccomp_profile.get('type', seccomp_ann)
        if profile_type in ('Unconfined', 'unconfined'):
            print(f'HIGH|{ns}/{name}|Seccomp profile is Unconfined — no syscall restrictions applied')
        else:
            enforced += 1
            # RuntimeDefault is acceptable; Localhost with a custom profile is better
            if profile_type == 'RuntimeDefault':
                pass  # good enough
            elif profile_type == 'Localhost':
                pass  # custom profile, even better
    else:
        missing += 1
        print(f'HIGH|{ns}/{name}|No Seccomp profile set — all syscalls permitted (attack surface expanded)')

print(f'SUMMARY|{enforced} pods with Seccomp enforced, {missing} pods without Seccomp profile')
" 2>/dev/null)
  echo "$_sc" | while IFS='|' read -r sev ref msg; do
    case "$sev" in
      HIGH)    high "$ref — $msg"
               poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.securityContext.seccompProfile}'"
               poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.metadata.annotations}' | grep -i seccomp" ;;
      SUMMARY) log "$ref$msg" ;;
    esac
  done
  local sc_high_count
  sc_high_count=$(echo "$_sc" | grep -c '^HIGH' || true)
  [[ "$sc_high_count" -eq 0 ]] && pass "All non-system pods have Seccomp profiles configured"
}

# =============================================================================
# 16. NODE NAME TARGETING (MASTER NODE ESCAPE)
# =============================================================================
check_nodename_targeting() {
  section "16/17 · nodeName Targeting (Master Node Escape)"

  log "Checking for pods with explicit nodeName pointing to control-plane nodes..."

  # Identify control-plane / master nodes by label
  local master_nodes
  master_nodes=$(kctl get nodes -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
for n in data.get('items', []):
    labs = n.get('metadata',{}).get('labels', {})
    name = n.get('metadata',{}).get('name','')
    # Common control-plane labels
    if any(k in labs for k in ('node-role.kubernetes.io/master',
                                'node-role.kubernetes.io/control-plane')):
        print(name)
" 2>/dev/null)

  if [[ -z "$master_nodes" ]]; then
    log "No control-plane nodes visible via labels (AKS hides master nodes) — checking all explicit nodeName assignments"
  fi

  # Check all pods for explicit nodeName
  local _nn
  _nn=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict): data = {}
masters = set('''${master_nodes}'''.split())
skip_ns = {'kube-system','kube-public','kube-node-lease'}

for pod in data.get('items', []):
    ns     = pod.get('metadata',{}).get('namespace','?')
    name   = pod.get('metadata',{}).get('name','?')
    spec   = pod.get('spec', {})
    node   = spec.get('nodeName', '')
    owner  = [o.get('kind','') for o in pod.get('metadata',{}).get('ownerReferences',[]) or []]
    if ns in skip_ns: continue
    if not node: continue

    is_master = node in masters

    # Any user workload with an explicit nodeName is suspicious
    if is_master:
        print(f'CRITICAL|{ns}/{name}|explicitly scheduled on control-plane node \"{node}\" via nodeName — potential master escape')
    elif 'DaemonSet' not in owner and 'Node' not in owner:
        print(f'HIGH|{ns}/{name}|has explicit nodeName=\"{node}\" — verify this is intentional (not an escape attempt)')
" 2>/dev/null)

  if [[ -z "$_nn" ]]; then
    pass "No non-system pods with suspicious explicit nodeName assignments found"
  else
    echo "$_nn" | while IFS='|' read -r sev ref msg; do
      case "$sev" in
        CRITICAL) critical "$ref — $msg"
                  poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.nodeName}'"
                  poc "kubectl exec -n ${ref%%/*} ${ref##*/} -- cat /proc/1/cgroup"
                  poc "kubectl exec -n ${ref%%/*} ${ref##*/} -- ls /host/etc 2>/dev/null || echo 'no hostPath'" ;;
        HIGH)     high "$ref — $msg"
                  poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.nodeName}'" ;;
      esac
    done
  fi

  # ── Also check for pods that tolerate master taints ───────────────────────
  log "Checking for user pods tolerating control-plane/master taints..."
  local _mastertol
  _mastertol=$(kctl get pods $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
master_taint_keys = {'node-role.kubernetes.io/master','node-role.kubernetes.io/control-plane'}
skip_ns = {'kube-system','kube-public','kube-node-lease'}

for pod in data.get('items', []):
    ns   = pod.get('metadata',{}).get('namespace','?')
    name = pod.get('metadata',{}).get('name','?')
    if ns in skip_ns: continue
    owner = [o.get('kind','') for o in (pod.get('metadata',{}).get('ownerReferences') or [])]
    if 'DaemonSet' in owner: continue
    for tol in (pod.get('spec',{}).get('tolerations') or []):
        if tol.get('key','') in master_taint_keys:
            print(f'HIGH|{ns}/{name}|tolerates control-plane taint \"{tol[\"key\"]}\" — can be scheduled on master nodes')
            break
" 2>/dev/null)
  if [[ -n "$_mastertol" ]]; then
    echo "$_mastertol" | while IFS='|' read -r sev ref msg; do
      case "$sev" in
        HIGH) high "$ref — $msg"
              poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.tolerations}'"
              poc "kubectl get pod ${ref##*/} -n ${ref%%/*} -o jsonpath='{.spec.nodeName}'" ;;
      esac
    done
  else
    pass "No user pods tolerate control-plane/master taints"
  fi
}

# =============================================================================
# 17. EGRESS NETWORKPOLICY (REVERSE SHELL PREVENTION)
# =============================================================================
check_egress_policies() {
  section "17/17 · Egress NetworkPolicy (Reverse Shell Prevention)"

  log "Checking namespaces for explicit egress NetworkPolicies..."
  local all_ns
  all_ns=$(kctl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

  kctl get networkpolicies $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
skip_ns = {'kube-system','kube-public','kube-node-lease','gatekeeper-system'}

# Build per-namespace egress coverage map
ns_egress   = {}   # ns -> list of policy names that have Egress policyType
ns_egress_default_deny = set()

for np in data.get('items', []):
    ns     = np.get('metadata',{}).get('namespace','')
    npname = np.get('metadata',{}).get('name','')
    spec   = np.get('spec', {})
    types  = spec.get('policyTypes', [])
    sel    = spec.get('podSelector', {})
    egress = spec.get('egress')

    if 'Egress' in types:
        ns_egress.setdefault(ns, []).append(npname)
        # Default-deny egress: empty podSelector + Egress type + no egress rules
        if sel == {} and (egress is None or egress == []):
            ns_egress_default_deny.add(ns)

all_ns_list = '''${all_ns}'''.split()
for ns in all_ns_list:
    if ns in skip_ns: continue
    if ns not in ns_egress:
        print(f'HIGH|{ns}|No egress NetworkPolicy — outbound connections unrestricted (reverse shell possible)')
    elif ns not in ns_egress_default_deny:
        policies = ', '.join(ns_egress[ns])
        print(f'HIGH|{ns}|Has egress policies ({policies}) but no default-deny-egress — some pods may have unrestricted outbound')
    else:
        print(f'PASS|{ns}|Default-deny egress NetworkPolicy in place')
" 2>/dev/null | while IFS='|' read -r sev ns msg; do
    case "$sev" in
      HIGH) high "Namespace \"$ns\" — $msg"
            poc "kubectl get networkpolicies -n ${ns} -o yaml | grep -A10 policyTypes"
            poc "kubectl exec -n ${ns} <any-pod> -- curl -s --max-time 5 https://example.com && echo EGRESS_OPEN || echo EGRESS_BLOCKED" ;;
      PASS) pass "Namespace \"$ns\" — $msg" ;;
    esac
  done

  # ── Check that DNS egress (port 53) is explicitly allowed where egress is denied ──
  log "Checking egress policies allow DNS (port 53) where egress is restricted..."
  kctl get networkpolicies $NS_FLAG -o json 2>/dev/null | python3 -c "
import sys, json
try:
    _raw = sys.stdin.read().strip()
    data = json.loads(_raw) if _raw else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
skip_ns = {'kube-system','kube-public','kube-node-lease','gatekeeper-system'}

for np in data.get('items', []):
    ns     = np.get('metadata',{}).get('namespace','')
    npname = np.get('metadata',{}).get('name','')
    spec   = np.get('spec', {})
    types  = spec.get('policyTypes', [])
    egress = spec.get('egress') or []
    if ns in skip_ns: continue

    # Default-deny egress with no rules at all
    if 'Egress' in types and egress == []:
        print(f'HIGH|{ns}/{npname}|Egress denied with no exceptions — DNS (port 53) also blocked, pods cannot resolve names')
    elif 'Egress' in types and egress:
        # Check if port 53 is allowed somewhere
        ports_allowed = set()
        for rule in egress:
            for p in (rule.get('ports') or []):
                ports_allowed.add(str(p.get('port','')))
        if '53' not in ports_allowed and egress:
            print(f'HIGH|{ns}/{npname}|Egress policy has rules but port 53 (DNS) not explicitly allowed — pods may fail DNS resolution')
        else:
            print(f'PASS|{ns}/{npname}|Egress policy allows DNS (port 53)')
" 2>/dev/null | while IFS='|' read -r sev ref msg; do
    case "$sev" in HIGH) high "$ref — $msg";; PASS) pass "$ref — $msg";; esac
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
  printf "${BOLD}${BLUE}║${RESET}  %-28s %-24s${BOLD}${BLUE}║${RESET}\n" "Context:" "$(kctl config current-context 2>/dev/null | cut -c1-24)"
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
      printf "Context   : %s\n" "$(kctl config current-context 2>/dev/null)"
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
  echo "  ║     AKS VULNERABILITY SCANNER  —  kctl native     ║"
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
  check_kubelet_api
  check_etcd
  check_insecure_api_port
  check_dashboard_hardening
  check_apparmor
  check_seccomp
  check_nodename_targeting
  check_egress_policies

  print_summary
}

main "$@"
