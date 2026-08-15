#!/bin/sh
# Bulk-links every team with a given product enabled to a named Organization.
#
# Written for the Clann -> tack-server notes migration
# (/Users/colin/.claude/plans/linked-roaming-rabbit.md, "Phase 0") to
# replicate in local/dev what was already done manually in production:
# an Organization "Clann" was created and every Clann team linked to it.
# No bulk-link endpoint exists anywhere in this codebase -- organization_id
# is just another field on `PATCH /admin/teams/{id}` (see admin.rs's own
# "Admin: Organizations" comment), one team per call. This script loops
# that call over every team with the given product enabled.
#
# Idempotent: re-running is safe. A team already linked to the target org
# is left alone (and reported as "[ok]", not re-PATCHed) so drift is
# visible in the output; a team linked to a *different* org is corrected
# and reported as "[changed]" with both the old and new value logged.
#
# Usage:
#   BASE_URL=http://localhost:8081 ADMIN_TOKEN=<admin bearer> \
#     ./link_teams_to_organization.sh --dry-run
#
#   BASE_URL=http://localhost:8081 ADMIN_TOKEN=<admin bearer> \
#     ./link_teams_to_organization.sh
#
# Env vars:
#   BASE_URL      ullav-user-management base URL (default http://localhost:8081)
#   ADMIN_TOKEN   required -- an admin bearer token
#   ORG_NAME      organization name to look up/create (default "Clann")
#   PRODUCT_SLUG  product slug identifying which teams to link (default "clann")
#
# Flags:
#   --dry-run     print what would happen, make zero POST/PATCH calls

set -e

BASE_URL="${BASE_URL:-http://localhost:8081}"
ADMIN_TOKEN="${ADMIN_TOKEN:?set ADMIN_TOKEN to an admin bearer token}"
ORG_NAME="${ORG_NAME:-Clann}"
PRODUCT_SLUG="${PRODUCT_SLUG:-clann}"

DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
    esac
done

api() {
    method="$1"
    path="$2"
    body="$3"
    if [ -n "$body" ]; then
        curl -sf -X "$method" "$BASE_URL$path" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body"
    else
        curl -sf -X "$method" "$BASE_URL$path" \
            -H "Authorization: Bearer $ADMIN_TOKEN"
    fi
}

echo "==> Looking up organization '$ORG_NAME' (exact name match)..."
existing_org_id=$(api GET "/admin/organizations" | jq -r --arg name "$ORG_NAME" '.[] | select(.name == $name) | .id' | head -1)

if [ -n "$existing_org_id" ] && [ "$existing_org_id" != "null" ]; then
    org_id="$existing_org_id"
    echo "==> Found existing organization '$ORG_NAME': $org_id"
elif [ "$DRY_RUN" = "true" ]; then
    echo "==> [dry-run] No organization named '$ORG_NAME' exists -- would create it."
    org_id="<not-yet-created>"
else
    org_id=$(api POST "/admin/organizations" "{\"name\": \"$ORG_NAME\"}" | jq -r '.id')
    echo "==> Created organization '$ORG_NAME': $org_id"
fi

echo "==> Linking every team with product '$PRODUCT_SLUG' enabled to $org_id..."
page=1
page_size=50
total_seen=0

while true; do
    resp=$(api GET "/admin/teams?product=$PRODUCT_SLUG&page=$page&page_size=$page_size")
    team_count=$(echo "$resp" | jq '.teams | length')
    total=$(echo "$resp" | jq '.total')

    if [ "$team_count" -eq 0 ]; then
        break
    fi

    echo "$resp" | jq -c '.teams[]' | while IFS= read -r team; do
        team_id=$(echo "$team" | jq -r '.id')
        team_name=$(echo "$team" | jq -r '.name')
        current_org=$(echo "$team" | jq -r '.organization_id')

        if [ "$current_org" = "$org_id" ]; then
            echo "  [ok]      $team_name ($team_id) already linked to $org_id"
        elif [ "$DRY_RUN" = "true" ]; then
            echo "  [dry-run] $team_name ($team_id): $current_org -> $org_id"
        else
            api PATCH "/admin/teams/$team_id" "{\"organization_id\": \"$org_id\"}" > /dev/null
            echo "  [changed] $team_name ($team_id): $current_org -> $org_id"
        fi
    done

    total_seen=$((total_seen + team_count))
    if [ "$total_seen" -ge "$total" ]; then
        break
    fi
    page=$((page + 1))
done

echo "==> Done. Processed every team with product='$PRODUCT_SLUG' (organization: $ORG_NAME / $org_id)."
echo "==> Re-run any time -- already-linked teams are reported [ok], not re-written."
