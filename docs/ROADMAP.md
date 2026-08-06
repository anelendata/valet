# Valet Distributed Extension Roadmap

## Purpose

Valet currently protects a single computer: a sandboxed AI agent asks a trusted
host-side broker to run an approved operation, and Valet returns a redacted
result without exposing the credentials used by the operation.

The next evolution is to preserve that security model while allowing the caller,
the trusted execution host, and eventually a coordinating service to run on
different computers.

This roadmap defines three extensions:

1. **Level 1 — Trusted local-network RPC:** one Valet host, one or more clients
   on a trusted LAN.
2. **Level 2 — Internet relay:** clients and hosts communicate through a
   publicly reachable relay without opening an inbound port on the home network.
3. **Level 3 — Multi-party coordination:** multiple humans and agents share
   multiple Valet hosts with explicit identity, authorization, concurrency, and
   approval controls.

The levels are intentionally cumulative. Level 2 should reuse the Level 1 RPC
protocol. Level 3 should add coordination and policy around the Level 2 system,
not replace its transport or execution model.

---

## Product principle

Valet is not a remote shell and should not become one.

Its central abstraction is:

> A caller invokes a narrow capability. A trusted host evaluates policy, uses
> locally available credentials, performs the operation, redacts the result,
> and returns only the permitted output.

Network distribution must not weaken that boundary. In particular:

- credentials remain on the execution host;
- callers never receive raw environment variables, credential files, or tokens;
- the relay does not receive host credentials;
- policy is enforced on the execution host, even if an upstream relay also
  performs authorization;
- all returned output passes through the same redaction path as local calls;
- arbitrary shell execution remains a transitional compatibility feature, not
  the desired long-term public API;
- every request has a stable caller identity, request ID, and audit trail.

## Architectural direction

The client-facing interface should remain stable while the transport changes.
A human, script, or agent should invoke the same logical operation whether the
host is:

- on the same machine over a Unix domain socket;
- on the same LAN over WebSocket;
- behind a cloud relay over secure WebSocket;
- selected from multiple registered hosts.

Conceptually:

```text
CLI / REPL / agent integration
            |
       Valet client
            |
      RPC abstraction
            |
  +---------+----------+----------------+
  |                    |                |
Unix socket        LAN WebSocket    Relay WebSocket
  |                    |                |
  +---------------- Valet host ----------+
                       |
           policy -> execution -> redaction
                       |
                    result
```

The CLI and REPL should call a common client API such as:

```python
result = client.call(
    method="exec.run",
    params={"argv": ["handoff", "status"], "cwd": "..."},
)
```

They should not contain separate Unix-socket, HTTP, WebSocket, or relay logic.
Transport selection belongs behind the client abstraction.

---

# Level 1 — Trusted local-network RPC

## Goal

Allow a client on a second computer in the same trusted home network to use a
Valet host running on the primary computer, while preserving the existing CLI
and REPL experience.

Example:

```text
Local AI workstation                  Primary laptop
--------------------                  --------------
valet run -- handoff status  ------>  valet host
                                      local Handoff installation
                                      local AWS / BigQuery credentials
                              <------  redacted streamed result
```

The user should not need to craft HTTP requests. The same `valet` commands used
locally should work remotely after selecting a configured host.

## Scope

Level 1 includes:

- a transport-neutral RPC message model;
- WebSocket transport for bidirectional requests and streaming events;
- a client-only configuration that contains no host secrets;
- explicit host selection;
- persistent client identity;
- request correlation, cancellation, heartbeat, and reconnect behavior;
- integration with the existing CLI and REPL;
- audit records that distinguish local and LAN callers.

Level 1 does **not** include:

- public internet exposure;
- a cloud relay;
- browser access;
- organization accounts;
- complex role-based access control;
- a claim that an untrusted LAN is safe without encryption.

## Why WebSocket

Valet operations can be long-running and may stream stdout and stderr. A
persistent bidirectional connection is a better fit than treating every
operation as a short request-response exchange.

WebSocket provides:

- ordered messages over TCP;
- server-to-client output events without polling;
- cancellation over the same connection;
- heartbeat and liveness detection;
- a direct upgrade path from `ws://` on a trusted development LAN to `wss://`
  when encryption is required;
- broad library and reverse-proxy support.

WebSocket is only the transport. The RPC contract should be independently
specified and testable.

## RPC protocol v1

Use a small versioned envelope. JSON is sufficient for the first version because
it is inspectable and compatible with the existing JSON-oriented call model.
Binary framing or MessagePack can be considered only after measurements show a
real need.

### Request

```json
{
  "protocol": "valet-rpc/1",
  "type": "request",
  "request_id": "01K...",
  "client_id": "client_...",
  "method": "exec.run",
  "params": {
    "argv": ["handoff", "status"],
    "cwd": "/Users/daigo/projects/customer-etl"
  },
  "metadata": {
    "caller": "codex",
    "interactive": true
  }
}
```

### Stream event

```json
{
  "protocol": "valet-rpc/1",
  "type": "event",
  "request_id": "01K...",
  "sequence": 12,
  "event": "stdout",
  "data": "redacted output line\n"
}
```

Expected event types:

- `accepted` — host accepted the request for evaluation;
- `approval_required` — execution is paused awaiting approval;
- `started` — execution began;
- `stdout` — redacted stdout chunk;
- `stderr` — redacted stderr chunk;
- `progress` — structured progress update;
- `completed` — final status, exit code, duration, and counters;
- `failed` — protocol or execution failure;
- `cancelled` — cancellation completed.

### Control message

```json
{
  "protocol": "valet-rpc/1",
  "type": "cancel",
  "request_id": "01K..."
}
```

### Error model

Errors should be typed and safe to expose:

- `invalid_request`;
- `unsupported_protocol`;
- `unknown_method`;
- `authentication_failed`;
- `authorization_denied`;
- `policy_denied`;
- `approval_rejected`;
- `host_unavailable`;
- `operation_timeout`;
- `operation_failed`;
- `redaction_failed`;
- `internal_error`.

Internal stack traces, raw command output, and secret-bearing exceptions must not
be transmitted to the client.

## Separate host and client configuration

The current trusted host configuration may contain paths to credential sources,
redaction salts, policy, approval settings, and audit destinations. None of that
belongs on a remote client.

Introduce distinct configuration roles.

### Host configuration

Example responsibilities:

```toml
[host]
id = "daigo-main"
listen = "0.0.0.0:8766"
transport = "websocket"

[identity]
registry = "~/.valet/clients.json"

[redaction]
# Existing trusted secret-source configuration remains host-only.

[policy]
# Existing execution policy remains host-only.

[audit]
# Existing host audit configuration.
```

### Client configuration

Example:

```toml
[client]
id = "client-local-ai-box"
key_path = "~/.valet/identity/client.key"
default_host = "daigo-main"

[hosts.daigo-main]
url = "ws://192.168.1.25:8766/rpc"
server_public_key = "..."
```

The client configuration may contain an authentication credential specific to
that client, but must not contain the host's operational secrets, redaction
salt, AWS profiles, database credentials, or secret-source paths.

## Transport selection

Transport should be explicit and centralized. Avoid scattering automatic mode
checks throughout commands.

Recommended precedence:

1. an explicit CLI selection such as `--host daigo-main`;
2. the active profile in client configuration;
3. the configured default host;
4. local Unix-domain-socket transport as a backward-compatible default.

Examples:

```bash
valet run -- handoff status                     # configured default
valet --host daigo-main run -- handoff status   # explicit host
valet --local run -- handoff status             # force local UDS
valet hosts                                     # list configured hosts
valet host use daigo-main                       # change default
```

The CLI should resolve a `Target`, instantiate the appropriate transport, and
then use the same RPC client for all operations.

## Client identity and enrollment

Identity should be introduced in Level 1 even if the initial environment is a
single-user home LAN. Retrofitting identity after adding an internet relay would
be considerably harder.

### Rules

- no anonymous RPC calls;
- every installation creates a cryptographic key pair;
- `client_id` is stable and bound to a public key;
- a friendly name such as `local-ai-box` is display metadata, not the security
  identity;
- the private key never leaves the client computer;
- the host keeps an allowlisted client registry;
- identities can be revoked and rotated;
- every audit event records the authenticated client ID and claimed caller type.

### First-time enrollment

A practical home-LAN flow:

1. client generates a key pair and an enrollment request;
2. client displays a short fingerprint or one-time code;
3. the human runs an approval command on the trusted host;
4. host records the client public key and assigns allowed capabilities;
5. future connections authenticate by proving possession of the private key.

Example commands:

```bash
# Client
valet enroll ws://192.168.1.25:8766

# Host
valet clients pending
valet clients approve <request-id> --name local-ai-box
valet clients revoke <client-id>
```

Do not use a reusable shared password as the long-term identity mechanism.

## Authentication for Level 1

Even on a trusted LAN, authenticate both sides:

- the client proves its identity to the host;
- the client verifies that it connected to the expected host.

For the prototype, signed challenge-response authentication at the application
layer is acceptable. The protocol should be designed so TLS client certificates
or another standard mutual-authentication mechanism can replace it later
without changing RPC methods.

## CLI and REPL integration

The existing CLI and REPL should become consumers of the same RPC client.

Required behavior:

- streamed stdout and stderr retain their current terminal behavior;
- command exit codes propagate to the CLI;
- Ctrl-C sends cancellation before tearing down the connection;
- REPL `cd` state is represented as session state or explicit `cwd` values;
- reconnect does not silently re-run a non-idempotent operation;
- client output clearly identifies the selected host when it is remote;
- protocol and host errors are distinguishable from command exit failures.

A remote prompt might display:

```text
daigo-main:customer-etl valet>
```

## Reliability requirements

A persistent connection needs explicit lifecycle behavior:

- heartbeat/ping interval;
- idle timeout;
- maximum operation duration;
- bounded reconnect with jitter;
- request IDs generated client-side;
- monotonically increasing event sequence numbers;
- duplicate-request detection;
- final-result caching for a short period so a reconnecting client can learn
  whether a request completed;
- no automatic retry of operations unless the method is explicitly marked
  idempotent;
- cancellation that terminates the host process tree, not merely the stream.

## Level 1 implementation phases

### L1.1 — Extract an internal RPC boundary

- define method names, request/response types, and safe error types;
- route current Unix-domain-socket calls through the RPC abstraction;
- make CLI and REPL depend on a common `ValetClient`;
- preserve existing behavior and tests.

**Exit criterion:** local UDS behavior is unchanged, but no CLI command depends
directly on UDS implementation details.

### L1.2 — Add WebSocket server and client transports

- add WebSocket framing for RPC envelopes and stream events;
- implement heartbeat, cancellation, and orderly shutdown;
- add host binding configuration;
- keep `ws://` explicitly labeled as development/trusted-LAN only.

**Exit criterion:** a second computer can run `valet ping` and one read-only
streaming operation against a host on the LAN.

### L1.3 — Add client identity and enrollment

- generate client and host key pairs;
- implement challenge-response authentication;
- add enrollment, listing, rotation, and revocation commands;
- attach identity to policy and audit context.

**Exit criterion:** unknown clients are rejected, approved clients reconnect
without re-enrollment, and revoked clients cannot call any method.

### L1.4 — Unify CLI and REPL experience

- add host profiles and target selection;
- support remote streaming, exit codes, cancellation, and REPL sessions;
- add diagnostics such as `valet doctor`, `valet hosts`, and connection status.

**Exit criterion:** common workflows require no handwritten HTTP or WebSocket
messages and differ from local use only by host selection.

### L1.5 — Harden and document

- protocol fuzz tests and malformed-message tests;
- maximum frame, output, and concurrent-request limits;
- tests proving raw output cannot bypass redaction;
- LAN threat-model documentation;
- migration documentation for existing users.

**Level 1 completion criterion:** Valet can safely and conveniently broker
operations between two machines on a trusted LAN with authenticated identities,
streaming output, consistent audit records, and no client access to host secrets.

---

# Level 2 — Internet relay

## Goal

Allow an authorized traveling client to invoke capabilities on a home Valet host
without exposing the home computer or router directly to inbound internet
connections.

The home host initiates an outbound persistent connection to a publicly
reachable relay. The traveling client also connects to that relay. The relay
routes RPC messages between authenticated endpoints.

```text
Traveling client                 Cloud relay                  Home Valet host
---------------                 -----------                  ---------------
       |                            |                                |
       |------ outbound WSS ------>|<------- outbound WSS ----------|
       |                            |                                |
       |  encrypted RPC request    |                                |
       |-------------------------->|------------------------------->|
       |                            |      policy / execution         |
       |                            |      redaction                  |
       |<--------------------------|<-------------------------------|
       |  redacted stream/result   |                                |
```

No router port forwarding is required. Residential NAT remains closed to
unsolicited inbound traffic.

## Security pillars

Level 2 is governed by three major pillars.

### 1. Secure transport

Use `wss://`, not `ws://`, across the public internet.

WSS provides TLS encryption and server-certificate verification. Application
send/receive and RPC logic should remain unchanged; TLS configuration belongs to
the transport and deployment layers.

Requirements:

- TLS 1.2 minimum, TLS 1.3 preferred;
- trusted public certificates or a deliberately managed private trust root;
- strict hostname verification;
- no insecure certificate bypass flag in normal operation;
- certificate renewal and expiry monitoring;
- secret-free connection logs.

### 2. Strong authentication and explicit authorization

Authentication answers **who is this endpoint?** Authorization answers **what
may it do?** They must remain separate concepts.

Requirements:

- every client, host, relay service, and human actor has a stable identity;
- both the client and host authenticate to the relay;
- the client can verify the intended host, not merely the relay;
- short-lived session credentials replace long-lived bearer tokens where
  practical;
- credentials are revocable and rotatable;
- host policy remains authoritative for execution;
- relay authorization can further restrict routing but cannot grant a capability
  the host denies.

### 3. Controlled blast radius through least privilege

Assume any single component may eventually be compromised.

Requirements:

- the relay has no host operational credentials;
- callers receive capabilities, not a general shell;
- host credentials are read-only or narrowly scoped whenever possible;
- mutating capabilities require stronger policy and often human approval;
- rate, duration, output, concurrency, and target limits are enforced;
- host and client identities have per-capability grants;
- dangerous operations cannot be unlocked merely by gaining relay access.

## Relay responsibilities

The relay should be intentionally narrow:

- authenticate endpoints;
- maintain online host registrations;
- route request and event frames by host ID and request ID;
- enforce connection, rate, size, and concurrency limits;
- reject unauthorized client-to-host routing;
- record metadata-only audit events;
- support revocation and session expiry;
- provide operational health and administrative visibility.

The relay should not:

- store host credentials;
- execute host tools;
- receive raw secret files;
- make final host execution-policy decisions;
- silently rewrite RPC methods or parameters;
- persist command output by default;
- expose a generic TCP tunnel to arbitrary host ports.

## End-to-end encryption option

WSS protects each network leg. If the relay terminates TLS, it can ordinarily
read the RPC messages it forwards.

Two deployment modes should be recognized explicitly:

### Trusted relay mode

- client-to-relay and host-to-relay links use WSS;
- relay can inspect RPC payloads;
- simpler routing, observability, browser integration, and abuse controls;
- acceptable when the relay is operated as part of the trusted control plane.

### Blind relay mode

- WSS still protects each link;
- RPC payloads are additionally encrypted between client and host;
- relay sees routing metadata and opaque ciphertext;
- stronger protection against relay compromise;
- more difficult server-side authorization, diagnostics, browser access, and
  content-based controls.

The first implementation may use trusted relay mode, but the envelope should
reserve fields for end-to-end encryption and key agreement so blind relay mode
is not architecturally blocked.

## Outbound host connection

The home host runs a connector process, possibly integrated into `valet serve`:

```bash
valet connect relay.example.com --host daigo-main
```

Expected behavior:

- connection is always initiated outbound by the home host;
- relay registration proves possession of the host private key;
- heartbeats advertise liveness but not sensitive local metadata;
- reconnect uses bounded exponential backoff with jitter;
- offline periods are visible to clients;
- requests are not queued indefinitely by default;
- host software verifies relay identity before registration;
- host can disable relay access independently of local access.

## Internet client flow

Example:

```bash
valet --host daigo-main run -- handoff status
```

The client resolves `daigo-main` to the configured relay target, authenticates,
and sends the same RPC method used on the LAN. The client should not need to
know whether the host is local, relay-connected, or temporarily offline.

## Browser management console

A web console is useful at Level 2, but it should initially be an administrative
and approval interface, not a browser-based arbitrary shell.

Initial console functions:

- list known hosts and online status;
- list clients and identities;
- view capability grants;
- view safe audit metadata;
- approve or reject enrollment;
- revoke a client or host session;
- review and approve high-impact requests;
- terminate an active operation;
- inspect relay health.

Browser sessions require strong phishing-resistant authentication where
possible, CSRF protection, strict content security policy, secure cookies,
session expiry, re-authentication for sensitive actions, and complete audit
coverage.

## Level 2 threat model

Address at least these threats:

- attacker scans the public relay endpoint;
- credential stuffing or stolen browser session;
- malicious client impersonates an approved client;
- malicious relay impersonates a host;
- compromised host connector;
- compromised relay process or database;
- replayed RPC request;
- duplicated request after reconnect;
- denial-of-service through connection or output exhaustion;
- malicious command output attempts protocol injection;
- downgrade from WSS to WS;
- certificate expiry or trust-store failure;
- DNS or routing attack;
- unauthorized host enumeration;
- audit-log leakage;
- approval fatigue or misleading approval text.

## Level 2 implementation phases

### L2.1 — Harden WSS transport

- deploy TLS termination with automatic certificate renewal;
- require WSS and reject downgrade;
- test certificate rotation and hostname mismatch;
- add transport-level metrics without payload logging.

**Exit criterion:** all public-path traffic is WSS with verified certificates,
and insecure fallback is impossible in production configuration.

### L2.2 — Build a minimal single-user relay

- authenticate one operator's clients and hosts;
- register host presence;
- route versioned RPC envelopes and stream events;
- enforce basic quotas and offline behavior;
- keep execution policy on the host.

**Exit criterion:** a traveling CLI can invoke a read-only capability on the
home host without router changes or inbound host ports.

### L2.3 — Add relay administration

- identity inventory and revocation;
- host/client session visibility;
- metadata-only relay audit log;
- administrative CLI first, web console second;
- alerts for repeated authentication failures and unusual request rates.

**Exit criterion:** an operator can determine who connected, revoke access, and
trace a request across client, relay, and host audit IDs.

### L2.4 — Add approvals and high-impact controls

- classify methods by impact;
- require approval for configured methods or parameter patterns;
- bind approval to exact method, host, parameters, caller, and expiry;
- prevent parameter substitution after approval;
- provide cancellation and emergency relay disable.

**Exit criterion:** mutating operations cannot execute without the configured
approval, and the approval record is cryptographically or structurally bound to
the request that executed.

### L2.5 — Security review and recovery testing

- independent design review;
- penetration testing of relay and enrollment flows;
- key compromise and revocation drill;
- relay outage and reconnection drill;
- certificate-expiry drill;
- backup and restore of identity metadata;
- documented incident-response procedure.

**Level 2 completion criterion:** an authenticated remote client can securely
invoke explicitly authorized Valet capabilities over the internet through an
outbound-connected relay, with WSS, least privilege, bounded resource use,
revocation, approvals, and end-to-end audit correlation.

---

# Level 3 — Multi-party coordination

## Goal

Support multiple human users and AI agents concurrently accessing one or more
Valet hosts, while preserving clear identity, ownership, authorization,
coordination, and accountability.

Example:

```text
Human operator A -----+
                      |
Codex agent A --------+                    +---- laptop host
                      +---- relay/control -+
Local AI agent B -----+        plane       +---- home AI host
                      |                    +---- operations host
Human reviewer B -----+
```

Level 3 turns the relay from a single-user router into a control plane. It must
still avoid becoming a general-purpose remote execution platform.

## Actor model

Distinguish these entities:

- **human user** — a person who owns, requests, reviews, or approves work;
- **agent identity** — a particular agent installation or runtime;
- **client device** — the machine and key used to connect;
- **session** — a time-bounded authenticated interaction;
- **host** — a trusted Valet execution node;
- **organization/project** — an administrative and policy boundary;
- **capability** — a typed operation a host may perform;
- **request** — one invocation with immutable parameters;
- **task** — a higher-level unit that may contain several requests;
- **approval** — authorization for an exact action under explicit conditions.

Do not collapse human identity, agent identity, and device identity into a
single `caller` string. Audit records should be able to state, for example:

> Human Daigo authorized Codex agent `editor-agent` on device `macbook-01` to
> invoke `handoff.status` on host `daigo-main` for project `tiugo`, under policy
> version `abc123`.

## Authorization model

Begin with role-based policy, but allow capability- and resource-level
constraints.

Possible roles:

- operator;
- reviewer;
- read-only agent;
- deployment agent;
- host administrator;
- organization administrator;
- auditor.

Authorization inputs should include:

- organization and project;
- human principal;
- agent principal;
- client device;
- target host;
- method/capability;
- parameter constraints;
- time window;
- current approval state;
- request risk class;
- policy version.

The host must receive enough signed or verifiable context to enforce its own
policy. It must not blindly trust a mutable `role` field supplied by the client.

## Typed capabilities

Level 3 should accelerate migration away from arbitrary shell commands.

Examples:

```text
handoff.schedule.list
handoff.schedule.inspect
handoff.run.status
handoff.run.trigger
aws.ecs.service.describe
aws.logs.tail
bigquery.query.aggregate
artifact.fetch.sanitized
```

A capability definition should specify:

- input schema;
- output schema or stream-event schema;
- idempotency;
- read/write classification;
- risk class;
- required grants;
- approval requirement;
- allowable resources or projects;
- maximum runtime and output;
- redaction strategy;
- audit fields;
- implementation version.

Raw `exec.run` may remain for local compatibility but should be disabled by
default for multi-party internet use.

## Concurrency and coordination

Multiple actors introduce conflicts that do not exist in a one-client design.

Required controls:

- per-host and per-capability concurrency limits;
- resource locks for mutually exclusive operations;
- read-versus-write lock semantics where appropriate;
- request priority and fair scheduling;
- cancellation ownership and administrator override;
- task leases with expiration;
- detection of abandoned operations;
- idempotency keys for retry-safe methods;
- duplicate trigger prevention;
- visible operation ownership;
- explicit policy for whether two agents may operate on the same project
  simultaneously.

Avoid a single implicit global session. Every request must carry explicit task,
actor, host, and project context.

## Task state machine

Longer work should have a small, inspectable state model:

```text
submitted
  -> authorized
  -> awaiting_approval
  -> queued
  -> running
  -> succeeded | failed | cancelled | expired
```

Transitions should be append-only audit events. The current state can be derived
or materialized, but history should not be silently rewritten.

## Approval model

Approvals become first-class at Level 3.

An approval must bind to:

- exact requester identity;
- exact target host and project;
- exact capability and normalized parameters, or a narrowly defined parameter
  range;
- policy version;
- expiration time;
- number of allowed uses;
- approver identity;
- risk explanation shown to the approver.

Approval should not mean "allow this agent to do anything for the next hour."
Prefer one exact operation or a deliberately scoped batch.

For high-impact operations, support separation of duties: the requester cannot
approve their own request.

## Audit and observability

Correlate events across all components with a global request ID and task ID.

Audit should answer:

- who requested the operation;
- which human, agent, and device identities were involved;
- which host and capability were targeted;
- which policy version evaluated it;
- whether approval was required and who approved;
- when it queued, started, streamed, completed, failed, or was cancelled;
- which resources were affected;
- how much output was returned and how much redaction occurred;
- whether any component failed closed;
- whether the request crossed the relay or stayed local.

Do not centralize raw stdout/stderr merely for convenience. Preserve the current
principle that audit metadata should be useful without becoming a sensitive data
sink.

## Multi-tenant isolation

If Level 3 ever serves more than one organization, isolation must be designed,
not inferred.

Requirements:

- organization-scoped identities and host registrations;
- no cross-organization host discovery;
- organization-scoped encryption keys and audit access;
- authorization checks at every object lookup and route;
- quotas and rate limits per organization;
- secure deletion and retention controls;
- administrative actions that cannot cross tenants;
- tests specifically attempting tenant-boundary bypass.

A single-user control plane should not be advertised as multi-tenant merely
because it has multiple login accounts.

## Level 3 implementation phases

### L3.1 — Normalize principals and resources

- define human, agent, device, session, host, project, capability, request, task,
  and approval IDs;
- update audit schemas;
- introduce organization/project namespaces even if only one exists initially.

**Exit criterion:** every request can be attributed unambiguously to a human or
service owner, agent, device, session, project, and host.

### L3.2 — Add capability registry and scoped authorization

- register typed capability schemas and risk metadata;
- add grants by principal, host, project, and capability;
- provide policy simulation and explanation;
- begin disabling raw exec for remote multi-party clients.

**Exit criterion:** two agents can have meaningfully different permissions on
the same host, and denials explain which grant or constraint failed.

### L3.3 — Add task coordination

- task state machine;
- queues, leases, locks, idempotency keys, and concurrency quotas;
- ownership-aware cancellation;
- safe recovery after relay or host restart.

**Exit criterion:** simultaneous requests cannot accidentally duplicate a
protected operation or violate configured resource locking.

### L3.4 — Add multi-user approvals

- reviewer role;
- exact-request approval binding;
- separation of duties;
- expiry and one-time-use controls;
- web and CLI approval workflows.

**Exit criterion:** high-impact capabilities require an authorized reviewer and
cannot be altered or replayed after approval.

### L3.5 — Add organizational administration

- user and agent lifecycle;
- project and host ownership;
- policy versioning and rollout;
- audit search and export;
- organization quotas and retention;
- tenant-isolation testing if multiple organizations are supported.

**Level 3 completion criterion:** multiple humans and agents can safely share
Valet hosts under explicit, scoped, reviewable policy, with collision-resistant
coordination, bounded authority, strong approvals, and complete identity-aware
audit history.

---

# Cross-level design requirements

## Preserve local-first operation

Cloud availability must never become a prerequisite for local UDS operation.
The owner should retain a fully functional local mode if the relay is down or
intentionally disabled.

## Fail closed

When Valet cannot authenticate an actor, validate a message, load policy,
perform required redaction, verify an approval, or determine request state, it
must refuse or terminate the operation safely.

## Protocol versioning

- include protocol version in every envelope;
- negotiate supported versions during connection setup;
- reject unknown incompatible versions explicitly;
- version capability input/output schemas;
- document deprecation windows;
- never reinterpret an old method with broader authority.

## Backward compatibility

- preserve existing local CLI behavior through Level 1;
- route legacy commands through the new client/RPC abstraction;
- avoid a flag day for current configuration;
- provide config migration and diagnostics;
- keep existing redaction and audit tests as regression gates.

## Resource limits

At every network level enforce:

- maximum frame size;
- maximum request size;
- maximum output bytes;
- maximum runtime;
- maximum concurrent requests;
- per-client and per-host rate limits;
- bounded in-memory buffering;
- bounded reconnect and queue behavior.

Streaming is not a substitute for output limits.

## Secret-handling rules

- never send host secret-source configuration to a client or relay;
- never use operational credentials as Valet identity credentials;
- never log private keys, bearer credentials, raw authentication challenges, or
  unredacted payloads;
- store private identity keys in OS keychain/keyring or protected files;
- support rotation without renaming the logical client or host;
- ensure protocol errors pass through a safe error formatter;
- test redaction across message chunk boundaries.

## Testing strategy

Each level should include:

- unit tests for RPC schemas and authorization decisions;
- transport conformance tests shared by UDS and WebSocket;
- integration tests with streamed stdout/stderr and cancellation;
- reconnect and duplicate-request tests;
- malformed, oversized, reordered, and replayed message tests;
- identity enrollment, rotation, expiry, and revocation tests;
- redaction tests across arbitrary stream chunk boundaries;
- policy tests proving relay authorization cannot override host denial;
- fault injection for relay loss, host restart, client loss, and partial writes;
- end-to-end audit-correlation tests.

## Documentation deliverables

Before declaring each level complete, publish:

- architecture and data-flow diagram;
- threat model;
- protocol specification;
- configuration reference;
- enrollment and revocation guide;
- operational runbook;
- troubleshooting guide;
- upgrade and rollback guide;
- security limitations and non-goals.

---

# Recommended immediate work

The next implementation should remain narrowly focused on Level 1.

Recommended first sequence:

1. define the transport-neutral RPC interfaces and envelopes;
2. refactor the current UDS client/server path to use them without behavior
   changes;
3. add a client-only configuration model and explicit host profiles;
4. add WebSocket transport with streaming, cancellation, and heartbeat;
5. introduce client/host key identities and local enrollment;
6. connect the existing CLI and REPL to the common client;
7. harden limits, reconnect rules, redaction invariants, and audit fields;
8. document Level 1 before beginning the relay.

Do not begin the cloud relay by forwarding arbitrary HTTP requests to the
current host server. That would establish the wrong boundary and force identity,
streaming, protocol versioning, cancellation, and authorization to be retrofitted
under internet exposure.

The correct foundation is a small, explicit, authenticated RPC protocol whose
first two transports are the existing local Unix socket and a LAN WebSocket.
The cloud relay should later route that protocol, not invent a second one.


# Policy roadmap

The [`[policy]`](config.example.toml) section and [`valet/policy.py`](valet/policy.py)
carry the constraints. Available now:

- **command deny list** (`deny`) — refuse commands by program name.
- **built-in config protection** — `config.toml` is always refused as a
  command input or output target, including shell redirects. This guard is
  hard-coded and cannot be relaxed in `config.toml`; completion also hides the
  filename.
- **wildcard file bans** (`deny_read_paths`) — glob patterns (`**`, `*`, `?`) of
  files a command may not reference; valet refuses to run a command that names
  an existing matching file, so its content is never revealed. `**/.env` bans
  reading any `.env` anywhere; `~/.aws/**` bans anything under `~/.aws`. The
  analyzer is shell-aware: it splits on operators (`;` `&&` `||` `|` `&`,
  newlines) and tracks `cd`/`pushd`, so `cd some/dir; cat .env` is caught the
  same as `cat some/dir/.env`.

  It is still **best-effort static analysis of the command line**: it catches
  the realistic reveals (`cat`/`less`/`grep` a path, including after a `cd`), but
  cannot see through a computed path (`eval`, `$(...)`, variable expansion,
  base64) or a program that reads the file internally without naming it. Content
  redaction is the backstop for those; only OS-level sandboxing would stop a
  determined reader.
- **workspace read-jail** (`enforce_workspace_reads`) — when enabled, an
  existing file/directory argument, symlink target, or explicit `cwd` outside
  `[exec].workspace` is refused. This catches `cat ../message.txt` and
  `cd .. && cat message.txt`; it uses the same best-effort command-line analysis

Still to come:

  as `deny_read_paths` and is not an OS sandbox.
- **command allow list** (`allow`, empty = allow all today) becomes a strict
  allowlist when populated.
- **workspace write-jail** (`enforce_workspace_writes`) will forbid writes
  outside the configured `workspace`.
- **approval** for sensitive operations, especially actions that mutate
  infrastructure, deploy, spend money, delete data, or call out to less-trusted
  networks.
- **typed capabilities** for common workflows, so an agent can request
  `terraform_plan` or `gh_pr_checks` instead of a raw shell command string.

`Policy.check` is the single choke point; new constraints go there and stay
fail-closed.

