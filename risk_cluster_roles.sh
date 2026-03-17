#!/bin/bash

# Color codes
YELLOW="\033[1;33m"
BOLD_YELLOW="\033[1;93m"
RED="\033[1;31m"
CYAN="\033[1;36m"
GREEN="\033[1;32m"
MAGENTA="\033[1;35m"
RESET="\033[0m"

colorize_crb_line() {
  local line="$1"
  if [[ $line =~ ^(\[!\]\[ClusterRoleBinding\]→)\ ([^[:space:]]+)\ is\ binded\ to\ ([^[:space:]]+)\ ([^[:space:]]+)\.$ ]]; then
    local prefix="${BASH_REMATCH[1]}"
    local crb_name="${BASH_REMATCH[2]}"
    local subject_name="${BASH_REMATCH[3]}"
    local subject_kind="${BASH_REMATCH[4]}"
    
    echo -e "${GREEN}${prefix}${RESET} ${YELLOW}${crb_name}${RESET} is binded to ${CYAN}${subject_name}${RESET} ${MAGENTA}${subject_kind}${RESET}."
  else
    echo "$line"
  fi
}

colorize_rb_line() {
  local line="$1"
  if [[ $line =~ ^(\[!\]\[RoleBinding\]→)\ ([^[:space:]]+)\ is\ binded\ to\ ([^[:space:]]+)\ ([^[:space:]]+)\.$ ]]; then
    local prefix="${BASH_REMATCH[1]}"
    local rb_name="${BASH_REMATCH[2]}"
    local subject_name="${BASH_REMATCH[3]}"
    local subject_kind="${BASH_REMATCH[4]}"
    
    echo -e "${GREEN}${prefix}${RESET} ${YELLOW}${rb_name}${RESET} is binded to ${CYAN}${subject_name}${RESET} ${MAGENTA}${subject_kind}${RESET}."
  else
    echo "$line"
  fi
}

echo -e "${BOLD_YELLOW}[*] Started enumerating risky ClusterRoles:${RESET}"

kubectl get clusterroles -o json | jq -r '
  .items[]
  | select(.metadata.name | test("admin|cluster-admin|system|dev"; "i") | not)
  | {
      name: .metadata.name,
      perms: [
        .rules[]
        | select(
            (.resources[]? | contains("secrets"))
            or (.verbs[]? | test("create|list|update|delete|admin|bind"))
          )
        | (
            if (.resources[]? | contains("secrets")) then "list secrets" else empty end
          ),
          (
            if (.verbs[]? | test("create")) then "create resources" else empty end
          )
      ]
    }
  | select(.perms | length > 0)
' | jq -s '
  group_by(.name) 
  | map({
      name: .[0].name,
      perms: (map(.perms) | add | unique)
    }) 
  | .[] 
  | "\(.name) \(.perms | join("; "))"
' | while IFS= read -r line; do
  role=$(echo "$line" | cut -d' ' -f1)
  perms=$(echo "$line" | cut -d' ' -f2-)
  echo -e "${RED}[!][ClusterRole]→ ${role}${RESET}"
  IFS=';' read -ra PERMARR <<< "$perms"
  for p in "${PERMARR[@]}"; do
    p_trimmed="${p#"${p%%[![:space:]]*}"}"
    p_trimmed="${p_trimmed%"${p_trimmed##*[![:space:]]}"}"
    [[ -n "$p_trimmed" ]] && echo -e "    ${CYAN}- Has permission to ${p_trimmed}${RESET}"
  done
done

echo -e "\n${BOLD_YELLOW}[*] Started enumerating risky Roles:${RESET}"

kubectl get roles --all-namespaces -o json | jq -r '
  .items[]
  | select(.metadata.name | test("admin|cluster-admin|system|dev"; "i") | not)
  | {
      name: "\(.metadata.namespace)/\(.metadata.name)",
      perms: [
        .rules[]
        | select(
            (.resources[]? | contains("secrets"))
            or (.verbs[]? | test("create|list|update|delete"))
          )
        | (
            if (.resources[]? | contains("secrets")) then "list secrets" else empty end
          ),
          (
            if (.verbs[]? | test("create")) then "create resources" else empty end
          )
      ]
    }
  | select(.perms | length > 0)
' | jq -s '
  group_by(.name) 
  | map({
      name: .[0].name,
      perms: (map(.perms) | add | unique)
    }) 
  | .[] 
  | "\(.name) \(.perms | join("; "))"
' | while IFS= read -r line; do
  role=$(echo "$line" | cut -d' ' -f1)
  perms=$(echo "$line" | cut -d' ' -f2-)
  echo -e "${RED}[!][Role]→ ${role}${RESET}"
  IFS=';' read -ra PERMARR <<< "$perms"
  for p in "${PERMARR[@]}"; do
    p_trimmed="${p#"${p%%[![:space:]]*}"}"
    p_trimmed="${p_trimmed%"${p_trimmed##*[![:space:]]}"}"
    [[ -n "$p_trimmed" ]] && echo -e "    ${CYAN}- Has permission to ${p_trimmed}${RESET}"
  done
done

echo -e "\n${BOLD_YELLOW}[*] Started enumerating risky ClusterRoleBindings:${RESET}"

kubectl get clusterrolebindings -o json | jq -r '
  .items[]
  | select(.roleRef.name != null)
  | select(.roleRef.name | test("admin|cluster-admin|system|dev"; "i") | not)
  | . as $crb
  | $crb.roleRef.name as $role
  | $crb.subjects[]? 
  | select(.kind == "ServiceAccount" or .kind == "User" or .kind == "Group")
  | "[!][ClusterRoleBinding]→ \($crb.metadata.name) is binded to \(.name) \(.kind)."
' | uniq | while read -r line; do
  colorize_crb_line "$line"
done

echo -e "\n${BOLD_YELLOW}[*] Started enumerating risky RoleBindings:${RESET}"

kubectl get rolebindings --all-namespaces -o json | jq -r '
  .items[]
  | select(.roleRef.name != null)
  | select(.roleRef.name | test("admin|cluster-admin|system|dev"; "i") | not)
  | . as $rb
  | $rb.roleRef.name as $role
  | $rb.subjects[]? 
  | select(.kind == "ServiceAccount" or .kind == "User" or .kind == "Group")
  | "[!][RoleBinding]→ \($rb.metadata.name) is binded to \(.name) \(.kind)."
' | uniq | while read -r line; do
  colorize_rb_line "$line"
done
