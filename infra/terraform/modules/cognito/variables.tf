variable "region" {
  type = string
}

variable "resource_server_id" {
  description = "Audience of the downstream tools (Keycloak audience mock-enterprise)."
  type        = string
  default     = "mock-enterprise"
}

# Mirrors the client scopes in infra/keycloak/toolgate-realm.template.json.
variable "scopes" {
  type = map(string)
  default = {
    "members:read"  = "Read members"
    "policies:read" = "Read policies"
    "claims:read"   = "Read claims"
    "payments:read" = "Read payments"
    "comms:read"    = "Read communications"
    "claims:write"  = "Write claims"
    "members:write" = "Write members"
    "comms:write"   = "Send communications"
  }
}

# Agent clients from the Keycloak realm. Scopes follow policy/agents.yaml:
# core-read.* -> the five :read scopes, core-write.* -> claims:write and
# members:write, comms.* -> comms:write.
variable "agents" {
  type = map(list(string))
  default = {
    "servicing" = [
      "members:read", "policies:read", "claims:read", "payments:read", "comms:read",
      "claims:write", "members:write", "comms:write",
    ]
    "claims-intake" = [
      "members:read", "policies:read", "claims:read", "payments:read", "comms:read",
      "claims:write", "members:write", "comms:write",
    ]
    "fraud-triage" = [
      "members:read", "policies:read", "claims:read", "payments:read", "comms:read",
    ]
  }
}
