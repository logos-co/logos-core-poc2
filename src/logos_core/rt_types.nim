# src/logos_core/rt_types.nim
# Runtime Control contract types per LOGOS-MODULE-RUNTIME §9.2 / §9.3.
#
# Field names in the CBOR encoding match the CDDL exactly (snake_case); the
# Nim field names are camelCase (the encode/decode helpers in rt.nim map
# between the two). The `logos.schema_commitment` value is the conformant
# type from transport.nim (its CBOR keys are already snake_case).

import results
from ./transport import SchemaCommitment
from ./cbor_profile import cmpBytes

# ============================================================================
# `logos.runtime` supporting schema types (§9.2) — shared non-callable
# identities and addresses. tstr size bounds enforced at the boundary.
# ============================================================================

type
  ModuleName* = string ## tstr 1..64
  RuntimeInstanceId* = string ## tstr 1..128
  ModuleInstanceId* = string ## tstr 1..128
  ModuleProviderId* = string ## tstr 1..128
  RouteId* = string ## tstr 1..128
  ModuleStateAssignmentId* = string ## tstr 1..128

  ## `logos.runtime.module_instance_address`
  ModuleInstanceAddress* = object
    runtimeInstanceId*: RuntimeInstanceId
    moduleInstanceId*: ModuleInstanceId

  ## `logos.runtime.module_provider_address`
  ModuleProviderAddress* = object
    runtimeInstanceId*: Opt[RuntimeInstanceId]
    provider*: ModuleProviderId

# ============================================================================
# `logos.runtime_control` scalar types (§9.3)
# ============================================================================

type
  Reason* = string ## tstr 0..512
  AddressProfile* = string ## tstr 1..128
  DecisionId* = string ## tstr 1..128
  FailureCode* = string ## tstr 1..64
  HostName* = string ## tstr 1..255
  Port* = uint16
  Path* = string ## tstr 1..4096
  ServerName* = string ## tstr 1..255
  Alpn* = string ## tstr 1..255
  TrustAnchorId* = seq[byte] ## bstr 1..128
  SubjectPublicKeyInfo* = seq[byte] ## bstr 1..8192

  ## An explicit authority decision for one Runtime Control invocation
  ## (capability-authority: a real allow/deny, not a stub allow).
  AuthorityDecision* = object
    allowed*: bool
    decisionId*: DecisionId
    reason*: string ## tstr 0..512

  ## The Runtime's authority policy. The POC policy allows Runtime Control
  ## operations from authenticated module instances of this runtime; a real
  ## deployment supplies the policy records (grants/denials, scopes, audit).
  AuthorityPolicy* = object
    allowAuthenticated*: bool

# ============================================================================
# Module state / mode / route state
# ============================================================================

type
  ModuleState* {.pure.} = enum
    msUnloaded
    msLoaded
    msReady
    msStopping
    msError

  ModuleMode* {.pure.} = enum
    mmDirect
    mmLocalTransport
    mmRemoteTransport

  RouteState* {.pure.} = enum
    rsEstablishing
    rsReady
    rsDraining
    rsRevoked
    rsFailed
    rsClosed

proc stateName*(s: ModuleState): string =
  case s
  of msUnloaded: "unloaded"
  of msLoaded: "loaded"
  of msReady: "ready"
  of msStopping: "stopping"
  of msError: "error"

proc modeName*(m: ModuleMode): string =
  case m
  of mmDirect: "direct"
  of mmLocalTransport: "local-transport"
  of mmRemoteTransport: "remote-transport"

proc routeStateName*(s: RouteState): string =
  case s
  of rsEstablishing: "establishing"
  of rsReady: "ready"
  of rsDraining: "draining"
  of rsRevoked: "revoked"
  of rsFailed: "failed"
  of rsClosed: "closed"

## Terminal route states: once reached, a later renewal MUST fail (§9.1).
func isTerminalRouteState*(s: RouteState): bool =
  s in {rsRevoked, rsFailed, rsClosed}

# ============================================================================
# Runtime addresses (§9.3): unix-stream, tls-tcp, quic. NO plain tcp.
# ============================================================================

type
  RuntimeAddressKind* {.pure.} = enum
    rakUnixStream
    rakTlsTcp
    rakQuic

  UnixStreamRuntimeAddress* = object
    path*: Path
    profile*: Opt[AddressProfile]

  TlsTcpRuntimeAddress* = object
    host*: HostName
    port*: Port
    serverName*: Opt[ServerName]
    profile*: Opt[AddressProfile]

  QuicRuntimeAddress* = object
    host*: HostName
    port*: Port
    serverName*: Opt[ServerName]
    alpn*: Opt[Alpn]
    profile*: Opt[AddressProfile]

  ## `logos.runtime_control.runtime_address` (discriminated by transport)
  RuntimeAddress* = object
    kind*: RuntimeAddressKind
    unixStream*: UnixStreamRuntimeAddress
    tlsTcp*: TlsTcpRuntimeAddress
    quic*: QuicRuntimeAddress

  ## `logos.runtime_control.runtime_endpoint`
  RuntimeEndpoint* = object
    runtimeInstanceId*: Opt[RuntimeInstanceId]
    address*: RuntimeAddress

  ## `logos.runtime_control.remote_provider_target`
  RemoteProviderTarget* = object
    runtime*: RuntimeEndpoint
    provider*: Opt[ModuleProviderId]
    module*: Opt[ModuleName]

  ## `logos.runtime_control.remote_listener_address` (tls-tcp or quic only)
  RemoteListenerAddress* = object
    kind*: RuntimeAddressKind ## rakTlsTcp or rakQuic
    tlsTcp*: TlsTcpRuntimeAddress
    quic*: QuicRuntimeAddress

# ============================================================================
# Remote enrollment / listener / export records (§9.3) — POC: types only,
# remote enforcement is Phase 5.
# ============================================================================

type
  RemoteIdentityProfile* = string ## "logos.remote.tls-tcp" / "logos.remote.quic"

  RemoteRuntimeEnrollment* = object
    runtimeInstanceId*: RuntimeInstanceId
    profile*: RemoteIdentityProfile
    revision*: uint64
    status*: string ## "active" / "revoked"
    trustAnchor*: Opt[TrustAnchorId]
    subjectPublicKeys*: seq[SubjectPublicKeyInfo]

  RemoteListenerRecord* = object
    address*: RemoteListenerAddress
    enabled*: bool
    runtimeControlEnabled*: bool

  ProviderExportRecord* = object
    listener*: RemoteListenerAddress
    provider*: ModuleProviderAddress
    enabled*: bool

# ============================================================================
# Core records (§9.3)
# ============================================================================

type
  ## `logos.runtime_control.invocation_descriptor` (local | remote)
  InvocationDescriptor* = object
    kind*: string ## "local-transport" / "remote-transport"
    # local-transport fields
    profile*: Opt[string] ## "logos.local.unix-stream"
    path*: Opt[Path]
    ticket*: Opt[seq[byte]] ## bstr 32
    # remote-transport fields
    runtime*: Opt[RuntimeInstanceId]
    provider*: Opt[ModuleProviderId]
    endpoint*: Opt[RemoteListenerAddress]

  ## `logos.runtime_control.route_failure`
  RouteFailure* = object
    code*: FailureCode
    message*: Opt[Reason]

  ## `logos.runtime_control.route_access` (32-byte declaration roots).
  ## The `*Absent` flags distinguish an absent list (permits every declaration
  ## of that kind, RUNTIME §9.3) from a present empty list (permits none).
  RouteAccess* = object
    methods*: seq[seq[byte]] ## [* bstr 32]
    publishEvents*: seq[seq[byte]]
    subscribeEvents*: seq[seq[byte]]
    methodsAbsent*: bool ## absent methods list (permit all)
    publishEventsAbsent*: bool ## absent publish_events list (permit all)
    subscribeEventsAbsent*: bool ## absent subscribe_events list (permit all)

  ## `logos.runtime_control.module_record`
  ModuleRecord* = object
    module*: ModuleName
    provider*: Opt[ModuleProviderAddress]
    remote*: Opt[RemoteProviderTarget]
    instance*: Opt[ModuleInstanceId]
    stateAssignment*: Opt[ModuleStateAssignmentId]
    state*: ModuleState
    mode*: ModuleMode
    primaryContract*: Opt[SchemaCommitment]
    implements*: seq[SchemaCommitment]
    reason*: Opt[Reason]

  ## `logos.runtime_control.route_record`
  RouteRecord* = object
    route*: RouteId
    consumer*: ModuleInstanceAddress
    targetProvider*: ModuleProviderAddress
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]
    expectedContract*: Opt[SchemaCommitment]
    access*: RouteAccess
    state*: RouteState
    invocation*: Opt[InvocationDescriptor]
    decisionId*: Opt[DecisionId]
    expiresAt*: Opt[uint64]
    failure*: Opt[RouteFailure]

# ============================================================================
# Method request/response types (§9.3)
# ============================================================================

type
  ProviderRequirementCardinality* = string ## "single" / "all-runtime-visible"

  EstablishRouteRequest* = object
    requestKey*: string
    contract*: SchemaCommitment
    cardinality*: ProviderRequirementCardinality
    provider*: Opt[ModuleProviderAddress]
    access*: RouteAccess

  EstablishRouteResponse* = object
    routes*: seq[RouteRecord]
    partial*: bool

  RenewRouteRequest* = object
    requestKey*: string
    route*: RouteId

  RenewRouteResponse* = object
    route*: RouteRecord

  ListModulesRequest* = object

  ListModulesResponse* = object
    modules*: seq[ModuleRecord]
    partial*: bool

  ListRoutesRequest* = object
    module*: Opt[ModuleName]
    provider*: Opt[ModuleProviderAddress]

  ListRoutesResponse* = object
    routes*: seq[RouteRecord]
    partial*: bool

  CloseRouteRequest* = object
    route*: RouteId
    reason*: Opt[Reason]

  CloseRouteResponse* = object
    route*: RouteId
    state*: RouteState

  StartModuleRequest* = object
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]

  StartModuleResponse* = object
    module*: ModuleName
    instance*: ModuleInstanceId
    state*: ModuleState

  StopModuleRequest* = object
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]

  StopModuleResponse* = object
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]
    state*: ModuleState

  GetReadinessRequest* = object
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]

  GetReadinessResponse* = object
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]
    state*: ModuleState
    reason*: Opt[Reason]

  # -- remote listener / export (POC: local stub) --
  ListRemoteListenersRequest* = object
  ListRemoteListenersResponse* = object
    listeners*: seq[RemoteListenerRecord]
    partial*: bool

  SetRemoteListenerRequest* = object
    listener*: RemoteListenerRecord

  SetRemoteListenerResponse* = object
    listener*: RemoteListenerRecord

  ListProviderExportsRequest* = object
    listener*: Opt[RemoteListenerAddress]
    provider*: Opt[ModuleProviderAddress]

  ListProviderExportsResponse* = object
    exports*: seq[ProviderExportRecord]
    partial*: bool

  SetProviderExportRequest* = object
    exportRecord*: ProviderExportRecord ## CDDL key: "export"

  SetProviderExportResponse* = object
    exportRecord*: ProviderExportRecord ## CDDL key: "export"

  # -- state events --
  ModuleStateChangedEvent* = object
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]
    oldState*: ModuleState
    newState*: ModuleState
    reason*: Opt[Reason]

  RouteStateChangedEvent* = object
    route*: RouteId
    oldState*: RouteState
    newState*: RouteState
    module*: Opt[ModuleName]
    provider*: Opt[ModuleProviderAddress]
    reason*: Opt[Reason]

# ============================================================================
# Configuration methods (§9.3) — reference LOGOS-MODULE-CONFIGURATION types.
# POC: types only; the state machine + value records are Phase 5.
# ============================================================================

type
  ## `logos.module_configuration.schema_commitment` (distinct from the
  ## `logos.schema_commitment` above — a configuration schema document + root).
  ConfigSchemaCommitment* = object
    schemaDocument*: seq[byte]
    configurationRoot*: seq[byte]

  ConfigurationState* = string ## "absent" / "current" / "staged" / "error"

  GetConfigurationSchemaRequest* = object
    target*: ModuleInstanceAddress

  GetConfigurationSchemaResponse* = object
    target*: ModuleInstanceAddress
    stateRevision*: uint64
    schema*: ConfigSchemaCommitment

  GetConfigurationRequest* = object
    target*: ModuleInstanceAddress

  GetConfigurationResponse* = object
    target*: ModuleInstanceAddress
    state*: ConfigurationState

  UpdateConfigurationRequest* = object
    target*: ModuleInstanceAddress
    expectedStateRevision*: uint64
    expectedSchemaCommitment*: ConfigSchemaCommitment
    action*: string ## "stage" / "discard"
    value*: Opt[seq[byte]] ## configuration_value (stage only)

  UpdateConfigurationResponse* = object
    target*: ModuleInstanceAddress
    stateRevision*: uint64
    staged*: Opt[seq[byte]]

  ApplyConfigurationRequest* = object
    target*: ModuleInstanceAddress
    expectedStateRevision*: uint64

  ApplyConfigurationResponse* = object
    target*: ModuleInstanceAddress
    stateRevision*: uint64
    appliedValueRevision*: uint64

  ConfigurationStateChangedEvent* = object
    target*: ModuleInstanceAddress
    state*: ConfigurationState

# ============================================================================
# `route_access` scope validation (RUNTIME §9.3)
# ============================================================================

## Validate one present `route_access` list (RUNTIME §9.3): strictly
## ascending bytewise lexicographic order, no duplicates. An absent list is
## not validated (it permits every declaration of that kind).
func validateAccessList*(items: seq[seq[byte]]): Result[void, string] =
  for i in 1 ..< items.len:
    if cmpBytes(items[i - 1], items[i]) >= 0:
      return
        err("route_access list is not in strictly ascending order or has duplicates")
  ok()

## Validate the whole `route_access` value (RUNTIME §9.3). Each present list
## MUST be strictly ascending with no duplicates; the Runtime MUST NOT silently
## sort or deduplicate a received value.
func validateRouteAccess*(access: RouteAccess): Result[void, string] =
  if not access.methodsAbsent:
    ?validateAccessList(access.methods)
  if not access.publishEventsAbsent:
    ?validateAccessList(access.publishEvents)
  if not access.subscribeEventsAbsent:
    ?validateAccessList(access.subscribeEvents)
  ok()
