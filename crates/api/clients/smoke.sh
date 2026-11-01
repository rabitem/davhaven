#!/usr/bin/env bash
# Generates a Java and a TypeScript client from the committed OpenAPI document and compiles both.
#
# PLAN 4.2 asks for proof that the document is usable by client generators. This is that proof: if a construct
# of the document breaks OpenAPI Generator or yields code that does not compile, this script fails and names it.
#
# Usage: crates/api/clients/smoke.sh [path/to/openapi.json]
#
# The Java client also reads and writes fixtures/event.json and fixtures/problem.json (what the server sends for an
# event and for a problem) to prove that it understands the document, not only that it compiles, and reads both with
# enumeration values it does not know, as a later version of the API may send them. It reads and writes
# fixtures/event-write.json too, a write that removes a field (null) and leaves another alone (absent): the model has to
# keep the two apart (JsonNullable), and the TypeScript model has to admit null (src/smoke/nullable.ts).
#
# Needs JDK 17 or newer, Maven and Node.js with npm (all present on the CI runners). Everything that is resolved is
# pinned: OpenAPI Generator, the Maven plugin that prints the class path and the libraries of the client in pom.xml;
# Orval and TypeScript with all of their dependencies in package-lock.json, installed with 'npm ci --ignore-scripts'.
# The workflow runs for pull requests from forks, so nothing floats and no install script runs.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
spec="${1:-$here/../../../docs/openapi.json}"
spec="$(cd "$(dirname "$spec")" && pwd)/$(basename "$spec")"

if [ ! -f "$spec" ]; then
  echo "error: $spec does not exist (run 'cargo xtask contracts' first)" >&2
  exit 1
fi

cd "$here"
rm -rf target

echo "==> Tools: install the pinned TypeScript and Orval (npm ci)"
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
tsc="node_modules/.bin/tsc"
orval="node_modules/.bin/orval"

echo "==> Java: generate and compile (OpenAPI Generator, library native)"
mvn --batch-mode --no-transfer-progress -Dopenapi.spec="$spec" compile

echo "==> TypeScript: type-check the typescript-fetch client"
"$tsc" -p tsconfig.json

echo "==> TypeScript: generate a fetch client with Orval and type-check it"
"$orval" --input "$spec" --output target/orval/api.ts --client fetch
# A project file of its own (the same options, only Orval's output): TypeScript 7 refuses files on the command line next
# to a tsconfig.json.
"$tsc" -p tsconfig.orval.json

echo "==> Java: the generated model reads and writes the documents as the server sends them"
mvn --batch-mode --no-transfer-progress -q org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -Dmdep.outputFile=target/classpath.txt
classpath="target/classes:$(cat target/classpath.txt)"
mkdir -p target/smoke
javac -cp "$classpath" -d target/smoke src/smoke/Roundtrip.java
java -cp "target/smoke:$classpath" Roundtrip "$here/fixtures/event.json" "$here/fixtures/problem.json" \
  "$here/fixtures/event-write.json"

models="$(find target/generated/java -path '*client/model*' -name '*.java' | wc -l)"
operations="$(find target/generated/java -path '*client/api*' -name '*Api.java' | wc -l)"
echo "==> ok: ${models} Java model classes, ${operations} API classes"
