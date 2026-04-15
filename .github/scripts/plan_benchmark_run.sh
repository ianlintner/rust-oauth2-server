#!/usr/bin/env bash
set -euo pipefail

DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
SINCE_DAYS="${SINCE_DAYS:-7}"
MANUAL_SERVERS="${MANUAL_SERVERS:-}"
FORCE_RUN="${FORCE_RUN:-false}"

ALL_SERVERS="rust rust-mongo keycloak hydra authentik node-oidc"
THIRD_PARTY_SERVERS="keycloak hydra authentik node-oidc"

has_output_file=false
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
	has_output_file=true
fi

log() {
	echo "[benchmark-plan] $*" >&2
}

selected_servers_csv=""
selection_reasons=""
third_party_version_bumps=""
changed_files_markdown=""
skip_reason=""
uses_repo_baselines="false"
has_first_party_changes="false"
has_third_party_version_bumps="false"

append_csv_value() {
	local value="$1"
	local current="$2"

	if [[ -z "$value" ]]; then
		printf '%s' "$current"
		return
	fi

	case ",${current}," in
		*,"${value}",*)
			printf '%s' "$current"
			;;
		*)
			if [[ -n "$current" ]]; then
				printf '%s,%s' "$current" "$value"
			else
				printf '%s' "$value"
			fi
			;;
	esac
}

append_selected_server() {
	local server="$1"
	selected_servers_csv="$(append_csv_value "$server" "$selected_servers_csv")"
}

append_markdown_line() {
	local current="$1"
	local line="$2"

	if [[ -z "$line" ]]; then
		printf '%s' "$current"
	elif [[ -n "$current" ]]; then
		printf '%s\n%s' "$current" "$line"
	else
		printf '%s' "$line"
	fi
}

append_selection_reason() {
	local line="$1"
	selection_reasons="$(append_markdown_line "$selection_reasons" "$line")"
}

append_version_bump() {
	local line="$1"
	third_party_version_bumps="$(append_markdown_line "$third_party_version_bumps" "$line")"
}

trim_whitespace() {
	local value="$1"
	value="${value#${value%%[![:space:]]*}}"
	value="${value%${value##*[![:space:]]}}"
	printf '%s' "$value"
}

csv_to_markdown_list() {
	local csv="$1"
	local output=""
	# IFS is declared with `local`, so it is scoped to this function and does not affect the global shell environment.
	local IFS=',' # nosemgrep: bash.lang.security.ifs-tampering
	read -r -a values <<< "$csv"

	for value in "${values[@]}"; do
		value="$(trim_whitespace "$value")"
		[[ -z "$value" ]] && continue
		output="$(append_markdown_line "$output" "- \`$value\`")"
	done

	printf '%s' "$output"
}

validate_server_name() {
	local server="$1"
	case "$server" in
		rust|rust-mongo|keycloak|hydra|authentik|node-oidc) return 0 ;;
		*) return 1 ;;
	esac
}

normalize_server_csv() {
	local raw_csv="$1"
	local normalized=""
	# IFS is declared with `local`, so it is scoped to this function and does not affect the global shell environment.
	local IFS=',' # nosemgrep: bash.lang.security.ifs-tampering
	read -r -a values <<< "$raw_csv"

	for value in "${values[@]}"; do
		value="$(trim_whitespace "$value")"
		[[ -z "$value" ]] && continue

		if ! validate_server_name "$value"; then
			echo "Unsupported benchmark server: $value" >&2
			exit 1
		fi

		normalized="$(append_csv_value "$value" "$normalized")"
	done

	printf '%s' "$normalized"
}

mark_first_party_change() {
	local reason="$1"
	has_first_party_changes="true"
	append_selection_reason "$reason"
}

compose_version_from_stream() {
	local image_prefix="$1"
	sed -n "s#.*${image_prefix}:\([^[:space:]]*\).*#\1#p" | head -n1
}

node_oidc_version_from_stream() {
	python3 -c 'import json,sys; print(json.load(sys.stdin).get("dependencies", {}).get("oidc-provider", ""))'
}

extract_version_from_stream() {
	local server="$1"
	case "$server" in
		keycloak) compose_version_from_stream 'quay.io/keycloak/keycloak' ;;
		hydra) compose_version_from_stream 'oryd/hydra' ;;
		authentik) compose_version_from_stream 'ghcr.io/goauthentik/server' ;;
		node-oidc) node_oidc_version_from_stream ;;
		*) printf '%s' '' ;;
	esac
}

version_file_for_server() {
	local server="$1"
	case "$server" in
		keycloak|hydra|authentik) printf '%s' 'benchmarks/docker-compose.yml' ;;
		node-oidc) printf '%s' 'benchmarks/setup/node-oidc/package.json' ;;
		*) printf '%s' '' ;;
	esac
}

extract_version_from_path() {
	local server="$1"
	local path
	path="$(version_file_for_server "$server")"
	[[ -z "$path" ]] && return 0

	extract_version_from_stream "$server" < "$path"
}

extract_version_from_ref() {
	local server="$1"
	local ref="$2"
	local path
	path="$(version_file_for_server "$server")"
	[[ -z "$path" || -z "$ref" ]] && return 0

	git show "${ref}:${path}" 2>/dev/null | extract_version_from_stream "$server" || true
}

write_output() {
	local key="$1"
	local value="$2"

	if [[ "$has_output_file" != "true" ]]; then
		return
	fi

	if [[ "$value" == *$'\n'* ]]; then
		{
			echo "${key}<<__GITHUB_OUTPUT_EOF__"
			printf '%s\n' "$value"
			echo "__GITHUB_OUTPUT_EOF__"
		} >> "$GITHUB_OUTPUT"
	else
		echo "${key}=${value}" >> "$GITHUB_OUTPUT"
	fi
}

since_date="$({
	SINCE_DAYS="$SINCE_DAYS" python3 - <<'PY'
import os
from datetime import datetime, timedelta, timezone

days = int(os.environ.get("SINCE_DAYS", "7"))
since = datetime.now(timezone.utc) - timedelta(days=days)
print(since.strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
} )"

default_ref="origin/${DEFAULT_BRANCH}"
head_sha="$(git rev-parse "$default_ref")"
recent_commit_count="$(git rev-list --count --since="$since_date" "$default_ref")"
base_sha="$(git rev-list -1 --before="$since_date" "$default_ref" 2>/dev/null || true)"

log "Inspecting ${default_ref} for benchmark-relevant changes since ${since_date}"

empty_tree_sha="$(git hash-object -t tree /dev/null)"
if [[ -n "$base_sha" ]]; then
	mapfile -t changed_files < <(git diff --name-only "$base_sha" "$head_sha" | sed '/^$/d')
else
	mapfile -t changed_files < <(git diff --name-only "$empty_tree_sha" "$head_sha" | sed '/^$/d')
fi

for file in "${changed_files[@]}"; do
	changed_files_markdown="$(append_markdown_line "$changed_files_markdown" "- \`$file\`")"

	case "$file" in
		Cargo.toml|Cargo.lock|Dockerfile|Dockerfile.ci|Dockerfile.prebuilt|application.conf|application.conf.example)
			mark_first_party_change "- first-party runtime or build input changed: \`$file\`"
			;;
		src/*|crates/*|oauth2-ratelimit/*|oauth2-resilience/*|migrations/*|templates/*|static/*)
			mark_first_party_change "- first-party code or assets changed: \`$file\`"
			;;
		benchmarks/docker-compose.yml|benchmarks/run-benchmarks.sh|benchmarks/analyze-results.sh)
			mark_first_party_change "- benchmark harness changed: \`$file\`"
			;;
		benchmarks/k6/*|benchmarks/setup/*)
			mark_first_party_change "- benchmark scenario or setup changed: \`$file\`"
			;;
		*)
			;;
	esac
done

for server in $THIRD_PARTY_SERVERS; do
	current_version="$(trim_whitespace "$(extract_version_from_path "$server")")"
	previous_version="$(trim_whitespace "$(extract_version_from_ref "$server" "$base_sha")")"

	if [[ -n "$current_version" && "$current_version" != "$previous_version" ]]; then
		has_third_party_version_bumps="true"
		append_selected_server "$server"
		append_version_bump "- \`$server\`: \`${previous_version:-<none>}\` → \`${current_version}\`"
	fi
done

manual_servers_csv="$(normalize_server_csv "$MANUAL_SERVERS")"

should_run="false"
if [[ -n "$manual_servers_csv" ]]; then
	selected_servers_csv="$manual_servers_csv"
	should_run="true"
	append_selection_reason "- manual override requested: ${manual_servers_csv}"
elif [[ "$has_first_party_changes" == "true" ]]; then
	append_selected_server rust
	append_selected_server rust-mongo
	should_run="true"
elif [[ "$has_third_party_version_bumps" == "true" ]]; then
	should_run="true"
fi

if [[ "$has_third_party_version_bumps" == "true" && -z "$manual_servers_csv" ]]; then
	append_selected_server rust
	append_selected_server rust-mongo
	append_selection_reason "- third-party version bump detected; rerunning first-party baseline plus changed external servers"
fi

if [[ "$FORCE_RUN" == "true" && "$should_run" != "true" ]]; then
	append_selected_server rust
	append_selected_server rust-mongo
	should_run="true"
	append_selection_reason "- force flag set; running first-party baseline even without qualifying changes"
fi

if [[ "$recent_commit_count" == "0" && -z "$manual_servers_csv" && "$FORCE_RUN" != "true" ]]; then
	should_run="false"
	skip_reason="No commits landed on ${DEFAULT_BRANCH} in the last ${SINCE_DAYS} day(s)."
elif [[ "$should_run" != "true" ]]; then
	skip_reason="Recent commits were found, but none matched the benchmark trigger rules."
fi

selected_servers_markdown="$(csv_to_markdown_list "$selected_servers_csv")"

unselected_servers_csv=""
for server in $ALL_SERVERS; do
	case ",${selected_servers_csv}," in
		*,"${server}",*) ;;
		*) unselected_servers_csv="$(append_csv_value "$server" "$unselected_servers_csv")" ;;
	esac
done

if [[ -n "$selected_servers_csv" && -n "$unselected_servers_csv" ]]; then
	uses_repo_baselines="true"
fi

log "Selected benchmark servers: ${selected_servers_csv:-<none>}"
if [[ -n "$skip_reason" ]]; then
	log "$skip_reason"
fi

write_output "since_date" "$since_date"
write_output "recent_commit_count" "$recent_commit_count"
write_output "should_run" "$should_run"
write_output "selected_servers_csv" "$selected_servers_csv"
write_output "selected_servers_markdown" "$selected_servers_markdown"
write_output "unselected_servers_csv" "$unselected_servers_csv"
write_output "uses_repo_baselines" "$uses_repo_baselines"
write_output "skip_reason" "$skip_reason"
write_output "changed_files_markdown" "$changed_files_markdown"
write_output "selection_reasons_markdown" "$selection_reasons"
write_output "has_first_party_changes" "$has_first_party_changes"
write_output "has_third_party_version_bumps" "$has_third_party_version_bumps"
write_output "third_party_version_bumps_markdown" "$third_party_version_bumps"

printf 'since_date=%s\n' "$since_date"
printf 'recent_commit_count=%s\n' "$recent_commit_count"
printf 'should_run=%s\n' "$should_run"
printf 'selected_servers_csv=%s\n' "$selected_servers_csv"
printf 'uses_repo_baselines=%s\n' "$uses_repo_baselines"

