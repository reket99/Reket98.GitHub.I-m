#!/bin/bash

echo "Listing pods behind ingresses via their services..."

# Get all ingress namespace, ingress name, and service names
kubectl get ingress --all-namespaces -o json | jq -r '
  .items[]
  | {namespace: .metadata.namespace, ingress: .metadata.name}
  | "\(.namespace) \(.ingress)"
' | while read -r ns ingress; do
  echo "== Ingress: $ingress (Namespace: $ns) =="

  # Get all service names used by this ingress
  services=$(kubectl get ingress "$ingress" -n "$ns" -o json | jq -r '
    .spec.rules[].http.paths[].backend.service.name
  ' | sort -u)

  if [ -z "$services" ]; then
    echo "  No backend services found."
    continue
  fi

  for svc in $services; do
    echo "  Service: $svc"

    # Get selector for the service
    selector=$(kubectl get svc "$svc" -n "$ns" -o jsonpath='{.spec.selector}' | jq -r 'to_entries | map("\(.key)=\(.value)") | join(",")')

    if [ -z "$selector" ]; then
      echo "    No selector found for service $svc."
      continue
    fi

    echo "    Selector: $selector"

    # List pods matching selector
    pods=$(kubectl get pods -n "$ns" -l "$selector" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

    if [ -z "$pods" ]; then
      echo "    No pods found for service $svc."
    else
      echo "    Pods:"
      echo "$pods" | sed 's/^/      - /'
    fi
  done

  echo ""
done
