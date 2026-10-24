variable "region" {
  type = string
}

# Resource servers mirror the Keycloak audiences. toolgate-gateway, core-read,
# core-write and comms each expose one `invoke` scope; mock-enterprise carries
# the eight client scopes from infra/keycloak/toolgate-realm.template.json.
variable "resource_servers" {
  type = map(list(string))
  default = {
    "toolgate-gateway" = ["invoke"]
    "core-read"        = ["invoke"]
    "core-write"       = ["invoke"]
    "comms"            = ["invoke"]
    "mock-enterprise" = [
      "members:read", "policies:read", "claims:read", "payments:read", "comms:read",
      "claims:write", "members:write", "comms:write",
    ]
  }
}

# App clients (client_credentials only), as `resource-server/scope`.
# - Agents get only toolgate-gateway/invoke: per-agent tool authorization is
#   enforced by the gateway policy (policy/agents.yaml), not by the IdP.
# - gateway calls the downstream servers (Keycloak audiences core-read,
#   core-write, comms).
# - Server clients carry exactly the mock-enterprise scopes of their Keycloak
#   clients.
variable "clients" {
  type = map(list(string))
  default = {
    "servicing"     = ["toolgate-gateway/invoke"]
    "claims-intake" = ["toolgate-gateway/invoke"]
    "fraud-triage"  = ["toolgate-gateway/invoke"]
    "gateway"       = ["core-read/invoke", "core-write/invoke", "comms/invoke"]
    "core-read" = [
      "mock-enterprise/members:read", "mock-enterprise/policies:read",
      "mock-enterprise/claims:read", "mock-enterprise/payments:read",
      "mock-enterprise/comms:read",
    ]
    "core-write" = ["mock-enterprise/claims:write", "mock-enterprise/members:write"]
    "comms"      = ["mock-enterprise/comms:write"]
  }
}
