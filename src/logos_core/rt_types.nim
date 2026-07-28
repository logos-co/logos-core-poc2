# src/logos_core/rt_types.nim
# Runtime Control schema types from LOGOS-MODULE-RUNTIME Section 9.1
# Field names match CDDL exactly (underscore_case) for direct Cbor.encode/decode
#
# These types can be passed to Cbor.encode() to produce an ordered map
# where the field names become the CBOR map keys.

import results

# ============================================================================
# Type aliases matching CDDL schema names
# ============================================================================

type
  ## Runtime Control type aliases - matching CDDL names exactly
  StateName* = string
  ModeName* = string
  RouteStateName* = string
  ModuleName* = string
  RuntimeInstanceId* = string
  ModuleProviderId* = string
  ModuleInstanceId* = string
  SchemaNamespace* = string
  RouteId* = string
  DescriptorKind* = string
  AuthorityRef* = string
  AuditRef* = string
  HostName* = string
  Port* = uint16
  Path* = string
  ServerName* = string
  Alpn* = string
  AddressProfile* = string
  FailureCode* = string
  Reason* = string
  SchemaModel* = string

# ============================================================================
# Runtime address types
# ============================================================================

type
  ## Runtime address transport tag
  RuntimeAddressTag* {.pure.} = enum
    ratUnixStream
    ratTcp
    ratTlsTcp
    ratQuic

  ## Per-transport address variants - field names match CDDL exactly
  UnixStreamAddress* = object
    transport*: string ## "unix-stream"
    path*: Path
    profile*: Opt[AddressProfile]

  TcpAddress* = object
    transport*: string ## "tcp"
    host*: HostName
    port*: Port
    profile*: Opt[AddressProfile]

  TlsTcpAddress* = object
    transport*: string ## "tls-tcp"
    host*: HostName
    port*: Port
    server_name*: Opt[ServerName]
    profile*: Opt[AddressProfile]

  QuicAddress* = object
    transport*: string ## "quic"
    host*: HostName
    port*: Port
    server_name*: Opt[ServerName]
    alpn*: Opt[Alpn]
    profile*: Opt[AddressProfile]

  ## Discriminated union for runtime address
  RuntimeAddress* = object
    tag*: RuntimeAddressTag
    unixStream*: UnixStreamAddress
    tcp*: TcpAddress
    tlsTcp*: TlsTcpAddress
    quic*: QuicAddress

  ## Runtime identity + address pair - field names match CDDL exactly
  RuntimeEndpoint* = object
    runtime_instance_id*: Opt[RuntimeInstanceId]
    address*: RuntimeAddress

  ## Target for a remote provider - field names match CDDL exactly
  RemoteProviderTarget* = object
    runtime*: RuntimeEndpoint
    provider*: Opt[ModuleProviderId]
    module*: Opt[ModuleName]

  ## Address of a provider record inside a runtime instance - field names match CDDL exactly
  ModuleProviderAddress* = object
    runtime_instance_id*: Opt[RuntimeInstanceId]
    provider*: ModuleProviderId

# ============================================================================
# Schema commitment
# ============================================================================

type
  ## Structural schema commitment - field names match CDDL exactly
  SchemaCommitment* = object
    commitment_model*: string
    schema_root*: seq[byte]
    hash_profile*: string
    hash_suite*: string

# ============================================================================
# Module state and mode enums
# ============================================================================

type
  ## Module lifecycle state
  ModuleState* {.pure.} = enum
    msUnloaded
    msLoaded
    msReady
    msStopping
    msError

  ## Module execution mode
  ModuleMode* {.pure.} = enum
    mmDirect
    mmLocalTransport
    mmRemoteTransport

  ## Route state
  RouteState* {.pure.} = enum
    rsEstablishing
    rsReady
    rsDraining
    rsRevoked
    rsFailed
    rsClosed

# ============================================================================
# String conversion helpers
# ============================================================================

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

proc stringToModuleState*(s: string): ModuleState =
  case s
  of "unloaded": msUnloaded
  of "loaded": msLoaded
  of "ready": msReady
  of "stopping": msStopping
  of "error": msError
  else: msError

proc stringToModuleMode*(s: string): ModuleMode =
  case s
  of "direct": mmDirect
  of "local-transport": mmLocalTransport
  of "remote-transport": mmRemoteTransport
  else: mmDirect

proc stringToRouteState*(s: string): RouteState =
  case s
  of "establishing": rsEstablishing
  of "ready": rsReady
  of "draining": rsDraining
  of "revoked": rsRevoked
  of "failed": rsFailed
  of "closed": rsClosed
  else: rsEstablishing

# ============================================================================
# Runtime Control records
# ============================================================================

type
  ## Invocation descriptor - field names match CDDL exactly
  InvocationDescriptor* = object
    kind*: ModuleMode
    descriptor_kind*: DescriptorKind
    descriptor*: Opt[seq[byte]]

  ## Route authority - field names match CDDL exactly
  RouteAuthority* = object
    authority_provider*: Opt[ModuleProviderAddress]
    authority_ref*: Opt[AuthorityRef]
    expires_at*: Opt[uint64]
    audit_ref*: Opt[AuditRef]

  ## Route failure info - field names match CDDL exactly
  RouteFailure* = object
    code*: FailureCode
    message*: Opt[Reason]

  ## Module record (runtime introspection) - field names match CDDL exactly
  ModuleRecord* = object
    module*: ModuleName
    provider*: Opt[ModuleProviderAddress]
    remote*: Opt[RemoteProviderTarget]
    instance*: Opt[ModuleInstanceId]
    state*: ModuleState
    mode*: ModuleMode
    schema_namespace*: Opt[SchemaNamespace]
    schema*: Opt[SchemaCommitment]
    reason*: Opt[Reason]

  ## Route record - field names match CDDL exactly
  RouteRecord* = object
    route*: RouteId
    caller_runtime*: RuntimeInstanceId
    target_provider*: ModuleProviderAddress
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]
    schema_namespace*: Opt[SchemaNamespace]
    schema*: Opt[SchemaCommitment]
    state*: RouteState
    invocation*: InvocationDescriptor
    authority*: Opt[RouteAuthority]
    failure*: Opt[RouteFailure]

# ============================================================================
# Runtime Control method request/response types
# These types match the CDDL schema for each method's request/response
# and can be passed to Cbor.encode() for CBOR serialization.
# ============================================================================

type
  ## Module record inline for list_modules_response
  ModuleRecordInline* = object
    module*: ModuleName
    provider*: Opt[ProviderAddressInline]
    remote*: Opt[RemoteProviderInline]
    instance*: Opt[ModuleInstanceId]
    state*: ModuleState
    mode*: ModuleMode
    schema_namespace*: Opt[SchemaNamespace]
    schema*: Opt[SchemaCommitment]
    reason*: Opt[Reason]

  ## Inline provider address (no runtime_instance_id)
  ProviderAddressInline* = object
    provider*: ModuleProviderId

  ## Inline remote provider (simplified)
  RemoteProviderInline* = object
    runtime*: RuntimeEndpointInline
    provider*: Opt[ModuleProviderId]
    module*: Opt[ModuleName]

  ## Inline runtime endpoint (no address for simplicity)
  RuntimeEndpointInline* = object
    runtime_instance_id*: Opt[RuntimeInstanceId]

  ## Route record inline for list_routes_response
  RouteRecordInline* = object
    route*: RouteId
    caller_runtime*: RuntimeInstanceId
    target_provider*: ModuleProviderAddress
    module*: ModuleName
    instance*: Opt[ModuleInstanceId]
    schema_namespace*: Opt[SchemaNamespace]
    schema*: Opt[SchemaCommitment]
    state*: RouteState
    invocation*: InvocationDescriptor
    authority*: Opt[RouteAuthority]
    failure*: Opt[RouteFailure]

## Request/Response types for each method
type
  ## list_modules response
  ListModulesResponse* = object
    modules*: seq[ModuleRecordInline]

  ## list_routes response
  ListRoutesResponse* = object
    routes*: seq[RouteRecordInline]

  ## revoke_route response
  RevokeRouteResponse* = object
    route*: RouteId
    state*: RouteState

  ## start_module response
  StartModuleResponse* = object
    module*: ModuleName
    instance*: string
    state*: ModuleState

  ## stop_module response
  StopModuleResponse* = object
    module*: ModuleName
    instance*: Opt[string]
    state*: ModuleState

  ## get_readiness response
  GetReadinessResponse* = object
    module*: ModuleName
    instance*: Opt[string]
    state*: ModuleState
    reason*: Opt[Reason]
