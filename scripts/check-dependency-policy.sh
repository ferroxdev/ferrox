#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

note() { printf '::error::%s\n' "$1"; status=1; }

allow_list="$(sed -n '/^\[licenses\]/,/^\[/p' deny.toml | sed -n 's/^  "\(.*\)",\{0,1\}$/\1/p')"

if [[ -z "$allow_list" ]]; then
  note "deny.toml's [licenses].allow is empty or unreadable, so this check would pass on nothing"
fi

metadata=""
if metadata="$(cargo metadata --offline --format-version 1 --all-features 2>/dev/null)"; then
  :
elif metadata="$(cargo metadata --format-version 1 --all-features 2>/dev/null)"; then
  :
else
  note "cargo metadata could not read the graph, so no licence was checked; run \`cargo fetch\` and try again"
  metadata=""
fi

if [[ -n "$metadata" ]]; then
  policy_check="$(mktemp "${TMPDIR:-/tmp}/ferrox-licences.XXXXXX")"
  trap 'rm -f "$policy_check"' EXIT
  cat >"$policy_check" <<'PY'
import json, re, sys

allow = {line.strip().lower() for line in sys.argv[1].splitlines() if line.strip()}
graph = json.load(sys.stdin)
expressions = sorted({p["license"] for p in graph["packages"] if p.get("license")})
failed = False

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.at = 0

    def peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def take(self, want=None):
        token = self.peek()
        if token is None or (want is not None and token.upper() != want):
            raise ValueError(f"expected {want or 'a licence id'}, found {token or 'end'}")
        self.at += 1
        return token

    def atom(self):
        token = self.take()
        if token == "(":
            value = self.disjunction()
            self.take(")")
            return value
        if token.upper() == "WITH":
            raise ValueError("WITH without a licence before it")
        if self.peek() is not None and self.peek().upper() == "WITH":
            self.take("WITH")
            token = f"{token} WITH {self.take()}"
        return token.lower() in allow

    def conjunction(self):
        value = self.atom()
        while self.peek() is not None and self.peek().upper() == "AND":
            self.take("AND")
            value = self.atom() and value
        return value

    def disjunction(self):
        value = self.conjunction()
        while self.peek() is not None and self.peek().upper() == "OR":
            self.take("OR")
            value = self.conjunction() or value
        return value

for expression in expressions:
    try:
        tokens = re.findall(r"\(|\)|[A-Za-z0-9.+-]+", expression.replace("/", " OR "))
        parser = Parser(tokens)
        passed = parser.disjunction()
        if parser.peek() is not None:
            raise ValueError(f"trailing token {parser.peek()}")
    except ValueError as error:
        print(f"::error::could not read licence expression `{expression}`: {error}")
        failed = True
        continue
    if not passed:
        print(f"::error::the graph carries `{expression}`, which names no licence `deny.toml` allows")
        failed = True

sys.exit(1 if failed else 0)
PY
  if ! printf '%s' "$metadata" | python3 "$policy_check" "$allow_list"; then
    status=1
  fi
fi

if grep -E '^source = "git\+' Cargo.lock >/dev/null; then
  grep -E '^source = "git\+' Cargo.lock | sort -u | while read -r _ line; do
    note "$line is not crates.io; deny.toml's [sources] allows no git source"
  done || true
  status=1
fi

for banned in sing-box v2ray-rust; do
  hits="$(grep -rnE "^[[:space:]]*${banned}[[:space:]]*=" --include='Cargo.toml' crates Cargo.toml 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    note "\`${banned}\` is a comparator, read at its pin under upstream/ and never a dependency"
    printf '%s\n' "$hits"
  fi
done

exit "$status"
