# Benign corpus sources

The 50 test-split benign definitions (`bn-01` ... `bn-50`) are tool definitions taken from
public open-source MCP servers and lightly adapted (see the `changes` column). They exist to
measure the scanner's false-positive rate. Each repository's LICENSE file was read on
2026-10-18 and confirmed MIT or Apache-2.0 before use. The copyright of each definition
remains with its upstream authors under the license shown.

## Repositories and license evidence

| Repository | License | LICENSE file |
|---|---|---|
| https://github.com/github/github-mcp-server | MIT | https://github.com/github/github-mcp-server/blob/main/LICENSE |
| https://github.com/modelcontextprotocol/servers | MIT (code predating the licensing transition; see note) | https://github.com/modelcontextprotocol/servers/blob/main/LICENSE |
| https://github.com/microsoft/playwright-mcp | Apache-2.0 | https://github.com/microsoft/playwright-mcp/blob/main/LICENSE |
| https://github.com/upstash/context7 | MIT | https://github.com/upstash/context7/blob/master/LICENSE |
| https://github.com/grafana/mcp-grafana | Apache-2.0 | https://github.com/grafana/mcp-grafana/blob/main/LICENSE |
| https://github.com/mongodb-js/mongodb-mcp-server | Apache-2.0 | https://github.com/mongodb-js/mongodb-mcp-server/blob/main/LICENSE |

Note on modelcontextprotocol/servers: its LICENSE states the project is moving from MIT to
Apache-2.0; contributions without relicensing consent stay MIT, new contributions are
Apache-2.0. Both are permitted licenses here. The definitions used (memory, git, fetch,
sequentialthinking) are recorded as MIT.

Note on playwright-mcp: the tool listing in its README is the source; the tool
implementations live in the Playwright repository.

Dev-split benign files (`dv-b-01` ... `dv-b-15`) are written fresh for this project, carry no
`source`, and reuse none of the definitions below.

## Definitions

| id | tool | repo | file path | license | changes |
|---|---|---|---|---|---|
| bn-01 | `get_me` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/get_me.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-02 | `get_file_contents` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/get_file_contents.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-03 | `create_or_update_file` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/create_or_update_file.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-04 | `list_pull_requests` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/list_pull_requests.snap` | MIT | verbatim from the toolsnap |
| bn-05 | `assign_copilot_to_issue` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/assign_copilot_to_issue.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-06 | `assign_copilot_to_issue_with_intent` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/assign_copilot_to_issue_with_intent.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-07 | `create_branch` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/create_branch.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-08 | `list_commits` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/list_commits.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-09 | `search_code` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/search_code.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-10 | `get_commit` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/get_commit.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-11 | `fork_repository` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/fork_repository.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-12 | `create_issue` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/create_issue.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-13 | `list_branches` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/list_branches.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-14 | `search_repositories` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/search_repositories.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-15 | `get_latest_release` | https://github.com/github/github-mcp-server | `pkg/github/__toolsnaps__/get_latest_release.snap` | MIT | verbatim from the toolsnap; icons, _meta and outputSchema fields dropped |
| bn-16 | `create_entities` | https://github.com/modelcontextprotocol/servers | `src/memory/index.ts` | MIT | schema converted from zod to JSON Schema; outputSchema omitted |
| bn-17 | `create_relations` | https://github.com/modelcontextprotocol/servers | `src/memory/index.ts` | MIT | schema converted from zod to JSON Schema; outputSchema omitted |
| bn-18 | `search_nodes` | https://github.com/modelcontextprotocol/servers | `src/memory/index.ts` | MIT | schema converted from zod to JSON Schema; outputSchema omitted |
| bn-19 | `open_nodes` | https://github.com/modelcontextprotocol/servers | `src/memory/index.ts` | MIT | schema converted from zod to JSON Schema; outputSchema omitted |
| bn-20 | `read_graph` | https://github.com/modelcontextprotocol/servers | `src/memory/index.ts` | MIT | description translated to Spanish (original: "Read the entire knowledge graph"); schema converted from zod; outputSchema omitted |
| bn-21 | `git_status` | https://github.com/modelcontextprotocol/servers | `src/git/src/mcp_server_git/server.py` | MIT | schema converted from pydantic model_json_schema to a plain JSON Schema (titles dropped) |
| bn-22 | `git_log` | https://github.com/modelcontextprotocol/servers | `src/git/src/mcp_server_git/server.py` | MIT | description translated to German (original: "Shows the commit logs"); parameter descriptions left in English; schema converted from pydantic model_json_schema to a plain JSON Schema (titles dropped) |
| bn-23 | `git_commit` | https://github.com/modelcontextprotocol/servers | `src/git/src/mcp_server_git/server.py` | MIT | schema converted from pydantic model_json_schema to a plain JSON Schema (titles dropped) |
| bn-24 | `git_add` | https://github.com/modelcontextprotocol/servers | `src/git/src/mcp_server_git/server.py` | MIT | schema converted from pydantic model_json_schema to a plain JSON Schema (titles dropped) |
| bn-25 | `git_create_branch` | https://github.com/modelcontextprotocol/servers | `src/git/src/mcp_server_git/server.py` | MIT | schema converted from pydantic model_json_schema to a plain JSON Schema (titles dropped) |
| bn-26 | `fetch` | https://github.com/modelcontextprotocol/servers | `src/fetch/src/mcp_server_fetch/server.py` | MIT | description verbatim; schema converted from pydantic (title fields dropped, numeric bounds approximated) |
| bn-27 | `sequentialthinking` | https://github.com/modelcontextprotocol/servers | `src/sequentialthinking/index.ts` | MIT | description verbatim; schema converted from zod (coerced types as plain types); outputSchema omitted |
| bn-28 | `browser_click` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-29 | `browser_navigate` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-30 | `browser_network_request` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-31 | `browser_network_requests` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-32 | `browser_find` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-33 | `browser_run_code_unsafe` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-34 | `browser_hover` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-35 | `browser_press_key` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-36 | `browser_select_option` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-37 | `browser_navigate_back` | https://github.com/microsoft/playwright-mcp | `README.md` | Apache-2.0 | description translated to French (original: "Go back to the previous page in the history"); taken from the README tool listing; schema reconstructed from the listed parameters (enums and array item types simplified) |
| bn-38 | `resolve-library-id` | https://github.com/upstash/context7 | `packages/mcp/src/index.ts` | MIT | description and annotations verbatim; schema converted from zod (preprocess alias wrapper dropped) |
| bn-39 | `query-docs` | https://github.com/upstash/context7 | `packages/mcp/src/index.ts` | MIT | description and annotations verbatim; schema converted from zod (preprocess alias wrapper dropped) |
| bn-40 | `search_dashboards` | https://github.com/grafana/mcp-grafana | `tools/search.go` | Apache-2.0 | description and annotations verbatim; schema converted from Go jsonschema struct tags (projectName parameter dropped where present) |
| bn-41 | `search_folders` | https://github.com/grafana/mcp-grafana | `tools/search.go` | Apache-2.0 | description and annotations verbatim; schema converted from Go jsonschema struct tags (projectName parameter dropped where present) |
| bn-42 | `list_prometheus_metric_metadata` | https://github.com/grafana/mcp-grafana | `tools/prometheus.go` | Apache-2.0 | description and annotations verbatim; schema converted from Go jsonschema struct tags (projectName parameter dropped where present) |
| bn-43 | `query_prometheus` | https://github.com/grafana/mcp-grafana | `tools/prometheus.go` | Apache-2.0 | description and annotations verbatim; schema converted from Go jsonschema struct tags (projectName parameter dropped where present) |
| bn-44 | `list_prometheus_metric_names` | https://github.com/grafana/mcp-grafana | `tools/prometheus.go` | Apache-2.0 | description and annotations verbatim; schema converted from Go jsonschema struct tags (projectName parameter dropped where present) |
| bn-45 | `query_prometheus_histogram` | https://github.com/grafana/mcp-grafana | `tools/prometheus.go` | Apache-2.0 | description and annotations verbatim; schema converted from Go jsonschema struct tags (projectName parameter dropped where present) |
| bn-46 | `find` | https://github.com/mongodb-js/mongodb-mcp-server | `packages/tools-mongodb/src/tools/read/find.ts` | Apache-2.0 | description verbatim; schema converted from zod (connection arguments and outputSchema omitted; no annotations in source) |
| bn-47 | `list-databases` | https://github.com/mongodb-js/mongodb-mcp-server | `packages/tools-mongodb/src/tools/metadata/listDatabases.ts` | Apache-2.0 | description verbatim; schema converted from zod (connection arguments and outputSchema omitted; no annotations in source) |
| bn-48 | `list-collections` | https://github.com/mongodb-js/mongodb-mcp-server | `packages/tools-mongodb/src/tools/metadata/listCollections.ts` | Apache-2.0 | description verbatim; schema converted from zod (connection arguments and outputSchema omitted; no annotations in source) |
| bn-49 | `drop-collection` | https://github.com/mongodb-js/mongodb-mcp-server | `packages/tools-mongodb/src/tools/delete/dropCollection.ts` | Apache-2.0 | description verbatim; schema converted from zod (connection arguments and outputSchema omitted; no annotations in source) |
| bn-50 | `count` | https://github.com/mongodb-js/mongodb-mcp-server | `packages/tools-mongodb/src/tools/read/count.ts` | Apache-2.0 | description verbatim; schema converted from zod (connection arguments and outputSchema omitted; no annotations in source) |
