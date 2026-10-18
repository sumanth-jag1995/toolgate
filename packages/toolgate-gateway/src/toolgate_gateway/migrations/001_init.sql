CREATE SCHEMA IF NOT EXISTS gateway;

CREATE TABLE IF NOT EXISTS gateway.audit_log (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    agent_id    text NOT NULL,
    client_id   text NOT NULL,
    tool        text NOT NULL,
    tool_hash   text,
    args_hmac   text NOT NULL,
    decision    text NOT NULL CHECK (decision IN (
        'allow', 'deny_unknown_tool', 'deny_scope', 'deny_unpinned',
        'deny_drift', 'deny_schema', 'deny_output', 'flag_output',
        'error_downstream')),
    reason      text,
    latency_ms  double precision,
    trace_id    text
);

CREATE TABLE IF NOT EXISTS gateway.pending_reviews (
    id            bigserial PRIMARY KEY,
    server_id     text NOT NULL,
    tool_name     text NOT NULL,
    observed_hash text,
    pinned_hash   text,
    reason        text,
    diff          text,
    findings      jsonb,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    UNIQUE NULLS NOT DISTINCT (server_id, tool_name, observed_hash)
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'toolgate_gateway_app') THEN
        CREATE ROLE toolgate_gateway_app LOGIN;
    END IF;
END
$$;

REVOKE ALL ON gateway.audit_log, gateway.pending_reviews FROM toolgate_gateway_app;
GRANT USAGE ON SCHEMA gateway TO toolgate_gateway_app;
GRANT INSERT ON gateway.audit_log TO toolgate_gateway_app;
GRANT USAGE ON SEQUENCE gateway.audit_log_id_seq TO toolgate_gateway_app;
GRANT SELECT, INSERT, UPDATE ON gateway.pending_reviews TO toolgate_gateway_app;
GRANT USAGE ON SEQUENCE gateway.pending_reviews_id_seq TO toolgate_gateway_app;
