# src/logos_core/shared_modules.nim
# Native module loading per LOGOS-MODULE-RUNTIME §2 (native
# implementation loading), §1.2/§1.3 (required exports, naming),
# §3.6 (artifact acceptance), and LOGOS-MODULE-INTERFACE §2.6
# (lifecycle + call surface), §5.2/§5.3 (ABI types, dynamic schema
# validation).
#
# Known-name resolution only: the expected flat module name is supplied
# by the resolved module record before executable mapping. There is no
# bootstrap discovery symbol.

import std/[os, strutils, dynlib, tables], results
import ./abi_types, ./cbor_profile, ./cdcddle, ./commitment, ./hash_profile

type
  ## One supporting schema entry of a provider contract.
  SupportingSchema* = object
    namespace*: string
    commitment*: seq[byte] # claimed 32-byte schema root
    document*: string
    schemaRoot*: seq[byte] # recomputed

  ## One validated provider contract (primary or implemented interface).
  CallSurfaceContract* = object
    commitment*: seq[byte] # claimed 32-byte schema root
    document*: string
    supporting*: seq[SupportingSchema]
    role*: SchemaRole
    namespace*: string
    declaredName*: string # _module or _interface value
    schemaRoot*: seq[byte] # recomputed
    methodNames*: seq[string] # bare method names
    hasEvents*: bool

  ## The validated provider-call-surface descriptor.
  CallSurface* = object
    primary*: Opt[CallSurfaceContract]
    interfaces*: seq[CallSurfaceContract]

  ## Artifact acceptance hook (RUNTIME §3.6). Phase 2 wires the
  ## interface; Phase 5 supplies the real authorization source.
  ArtifactAcceptance* = object
    ## Verify the exact artifact bytes; returns the bound digest.
    verify*: proc(path: string): Result[seq[byte], string]
    ## Check module-execution authorization for the expected name.
    authorize*: proc(path: string, moduleName: string): Result[void, string]

  ## One live module instance created from one successful _init().
  ModuleInstance* = object
    context*: LogosModuleContext
    destroyed*: bool
    # Per-instance services, retained until _destroy() returns
    # (INTERFACE §2.6: binding/callback/state valid and unchanged from
    # _init() entry until _destroy() returns).
    rcBinding*: ptr LogosRuntimeControlBinding
    publish*: LogosPublishFn
    publishUserData*: pointer
    stateDir*: string
    configCbor*: seq[byte]

  ## One accepted implementation binding: resolved symbols plus the
  ## validated call surface. Instances are created per _init().
  SharedModule* = object
    name*: string
    path*: string
    handle*: LibHandle
    # lifecycle (mandatory)
    nameFn*: LogosNameFn
    initFn*: LogosInitFn
    destroyFn*: LogosDestroyFn
    applyConfigurationFn*: Opt[LogosApplyConfigurationFn]
    # provider (present only when the module declares a provider contract)
    isProvider*: bool
    callSurfaceFn*: LogosCallSurfaceFn
    freeFn*: LogosFreeFn
    dispatchFn*: LogosDispatchFn
    surface*: CallSurface
    # live instances
    instances*: seq[ModuleInstance]

proc `=copy`*(a: var SharedModule, b: SharedModule) {.error.}

proc `=destroy`*(m: var SharedModule) =
  ## Graceful release: destroy every live instance, then unload.
  for idx in 0 ..< m.instances.len:
    if not m.instances[idx].destroyed and m.instances[idx].context != nil:
      m.destroyFn(m.instances[idx].context)
      m.instances[idx].destroyed = true
  if not m.handle.isNil:
    dynlib.unloadLib(m.handle)
    m.handle = nil

## ---------------------------------------------------------------------------
## Module naming (RUNTIME §1.3)

proc validModuleName*(name: string): bool =
  if name.len == 0 or name.len > 64:
    return false
  if not (name[0] in {'a' .. 'z'}):
    return false
  for c in name:
    if c notin {'a' .. 'z', '0' .. '9', '_'}:
      return false
  if "_call_" in name or "_publish_" in name:
    return false
  # `logos_*` names are reserved for Logos-defined runtime/system modules
  # (INTERFACE §naming); they are valid module names, not rejected. The
  # reservation is a spec-level concern (only Logos-defined modules may use
  # them), not a loader-level rejection.
  true

## ---------------------------------------------------------------------------
## CborValue helpers for closed-map validation

func mapKeys(m: CborValue): seq[string] =
  if m.kind != ckMap:
    return @[]
  for (k, v) in m.entries:
    if k.kind == ckText:
      result.add(k.s)

func mapGet(m: CborValue, key: string): CborValue =
  if m.kind != ckMap:
    return nil
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == key:
      return v

proc checkClosedMap*(
    m: CborValue, allowed: openArray[string], what: string
): Result[void, string] =
  ## closed map: exactly the allowed text keys, each present
  if m.kind != ckMap:
    return err(what & " is not a map")
  let keys = m.mapKeys()
  for k in keys:
    if k notin allowed:
      return err(what & " has unknown field " & k)
  for k in allowed:
    if k notin keys:
      return err(what & " is missing field " & k)
  ok()

proc checkCommitment*(cm: CborValue, what: string): Result[seq[byte], string] =
  ## validate one `logos.schema_commitment` value (INTERFACE §5.1)
  let r = checkClosedMap(
    cm,
    ["commitment_model", "hash_profile", "hash_suite", "schema_root"],
    what & " commitment",
  )
  if r.isErr:
    return err(r.error)
  let model = cm.mapGet("commitment_model")
  if model.kind != ckText or model.s != CommitmentModelRevision:
    return err(what & " commitment: wrong commitment_model")
  let profile = cm.mapGet("hash_profile")
  if profile.kind != ckText or profile.s != HashProfileId:
    return err(what & " commitment: wrong hash_profile")
  let suite = cm.mapGet("hash_suite")
  if suite.kind != ckText or suite.s != HashSuiteId:
    return err(what & " commitment: wrong hash_suite")
  let root = cm.mapGet("schema_root")
  if root.kind != ckBytes or root.by.len != 32:
    return err(what & " commitment: schema_root must be exactly 32 bytes")
  ok(root.by)

## ---------------------------------------------------------------------------
## Contract document validation (INTERFACE §2.6, §5.3)

proc metadataValue(rules: openArray[CddlRule], name: string): Opt[string] =
  for r in rules:
    if r.name == name:
      if r.body.kind == nkTstr:
        return Opt.some(r.body.s)
      return Opt.none(string)
  Opt.none(string)

proc hasRule(rules: openArray[CddlRule], name: string): bool =
  for r in rules:
    if r.name == name:
      return true
  false

proc methodNames(ctx: SchemaCtx): seq[string] =
  ## bare method names (qualified name minus the namespace prefix)
  for d in ctx.decls:
    if d.kind == dkMethod:
      result.add(d.name[ctx.namespace.len + 1 ..^ 1])

proc implementsValues(rules: openArray[CddlRule]): Result[seq[string], string] =
  ## the _implements value: an array of tstr literals
  var vals: seq[string]
  for r in rules:
    if r.name == "_implements":
      case r.body.kind
      of nkArray:
        for m in r.body.members:
          if m.ty.kind == nkTstr:
            vals.add(m.ty.s)
        return ok(vals)
      else:
        return err("_implements is not an array")
  ok(vals)

proc validateContract*(
    entry: CborValue,
    role: SchemaRole,
    moduleName: string,
    roots: var seq[seq[byte]],
    ifaceNamespaces: var seq[string],
): Result[CallSurfaceContract, string] =
  let r = checkClosedMap(
    entry, ["commitment", "document", "supporting_schemas"], "contract entry"
  )
  if r.isErr:
    return err(r.error)
  let cr = checkCommitment(entry.mapGet("commitment"), "contract")
  if cr.isErr:
    return err(cr.error)
  let claimedRoot = cr.get
  let docVal = entry.mapGet("document")
  if docVal.kind != ckText or docVal.s.len < 1 or docVal.s.len > MaxSchemaDocumentBytes:
    return err("contract document must be 1.." & $MaxSchemaDocumentBytes & " bytes")
  let doc = docVal.s

  let rulesR = parseCddl(doc)
  if rulesR.isErr:
    return err("contract document: " & rulesR.error)
  let rules = rulesR.get

  # supporting schemas (validated first: the primary document's references
  # resolve against them, so their roots must be known before the primary
  # document's schema root is recomputed — INTERFACE §2.6/§5.3, I1)
  let supVal = entry.mapGet("supporting_schemas")
  if supVal.kind != ckArray:
    return err("supporting_schemas is not an array")
  if role == roleInterface and supVal.items.len != 0:
    return err("interface supporting_schemas MUST be empty")
  var sup: seq[SupportingSchema]
  var supRefs: seq[SupportingRef]
  var supNamespaces: seq[string]
  for sv in supVal.items:
    let sr =
      checkClosedMap(sv, ["commitment", "document", "namespace"], "supporting entry")
    if sr.isErr:
      return err(sr.error)
    let nsVal = sv.mapGet("namespace")
    if nsVal.kind != ckText or nsVal.s.len < 1 or
        nsVal.s.len > MaxSupportingNamespaceBytes:
      return err(
        "supporting namespace must be 1.." & $MaxSupportingNamespaceBytes & " bytes"
      )
    let sdocVal = sv.mapGet("document")
    if sdocVal.kind != ckText or sdocVal.s.len < 1 or
        sdocVal.s.len > MaxSchemaDocumentBytes:
      return err("supporting document must be 1.." & $MaxSchemaDocumentBytes & " bytes")
    let scr = checkCommitment(sv.mapGet("commitment"), "supporting")
    if scr.isErr:
      return err(scr.error)
    let sclaimed = scr.get
    let sctxR = buildContext(sdocVal.s)
    if sctxR.isErr:
      return err("supporting document: " & sctxR.error)
    let sctx = sctxR.get
    if sctx.role != roleSupporting:
      return err("supporting document must be a supporting schema")
    if sctx.namespace != nsVal.s:
      return err("supporting namespace does not match its derived namespace")
    let smodelR = buildSchemaModel(sdocVal.s)
    if smodelR.isErr:
      return err("supporting document: " & smodelR.error)
    let smodel = smodelR.get
    let sroot = hashPayload(DomainSchemaRoot, smodel)
    if sroot != sclaimed:
      return err("supporting schema root mismatch for " & nsVal.s)
    if nsVal.s in supNamespaces:
      return err("duplicate supporting namespace " & nsVal.s)
    supNamespaces.add(nsVal.s)
    sup.add(
      SupportingSchema(
        namespace: nsVal.s, commitment: sclaimed, document: sdocVal.s, schemaRoot: sroot
      )
    )
    # Build the SupportingRef for reference resolution: the document's
    # recomputed schema root + each declaration's exact subtree root, so a
    # primary-document reference to it translates to an imported-reference
    # node (INTERFACE §5.3, COMMITMENT MODEL §9.1).
    let srefR = buildSupportingRef(sdocVal.s)
    if srefR.isErr:
      return err("supporting document: " & srefR.error)
    supRefs.add(srefR.get)
  # canonical order: namespace UTF-8 bytes, then schema-root bytes
  for i in 1 ..< sup.len:
    if sup[i - 1].namespace > sup[i].namespace or (
      sup[i - 1].namespace == sup[i].namespace and
      cmpBytes(sup[i - 1].schemaRoot, sup[i].schemaRoot) > 0
    ):
      return err("supporting schemas not in canonical order")
  # unused supporting schema check: every supporting namespace must be
  # referenced by name in the contract document.
  if role == roleConcrete:
    for s in sup:
      if s.namespace notin doc:
        return err("unused supporting schema " & s.namespace)

  # parse + recompute the primary document's schema root, resolving its
  # references against the separately supplied supporting schemas (INTERFACE
  # §2.6: the ABI caller MUST recompute every schema root and compare with
  # the claimed commitment before the provider is registered or invoked).
  let ctxR = buildContext(doc, supRefs)
  if ctxR.isErr:
    return err("contract document: " & ctxR.error)
  let ctx = ctxR.get
  if ctx.role != role:
    return err("contract document role is " & $ctx.role & ", expected " & $role)
  if role == roleConcrete:
    let modName = metadataValue(rules, "_module")
    if modName.isNone or modName.get != moduleName:
      return err("primary document _module must match the module name")
  else:
    if hasRule(rules, "_implements"):
      return err("interface document MUST NOT declare _implements")
    let ifaceName = metadataValue(rules, "_interface")
    if ifaceName.isNone or ifaceName.get != ctx.namespace:
      return err("interface document _interface must equal its derived namespace")

  let modelR = buildSchemaModel(doc, supRefs)
  if modelR.isErr:
    return err("contract document: " & modelR.error)
  let model = modelR.get
  let root = hashPayload(DomainSchemaRoot, model)
  if root != claimedRoot:
    return err("schema root mismatch for " & ctx.namespace)

  # duplicate contract identity
  for x in roots:
    if x == root:
      return err("duplicate contract identity in descriptor")
  roots.add(root)

  # duplicate interface namespace
  if role == roleInterface:
    if ctx.namespace in ifaceNamespaces:
      return err("duplicate interface namespace " & ctx.namespace)
    ifaceNamespaces.add(ctx.namespace)

  let declared =
    if role == roleConcrete:
      metadataValue(rules, "_module").get
    else:
      metadataValue(rules, "_interface").get
  var hasEvents = false
  for d in ctx.decls:
    if d.kind == dkEvent:
      hasEvents = true
  ok(
    CallSurfaceContract(
      commitment: claimedRoot,
      document: doc,
      supporting: sup,
      role: role,
      namespace: ctx.namespace,
      declaredName: declared,
      schemaRoot: root,
      methodNames: methodNames(ctx),
      hasEvents: hasEvents,
    )
  )

proc validateCallSurface*(
    raw: seq[byte], moduleName: string
): Result[CallSurface, string] =
  ## parse and validate the complete provider-call-surface descriptor
  if raw.len > MaxCallSurfaceBytes:
    return err("descriptor exceeds " & $MaxCallSurfaceBytes & " bytes")
  var top: CborValue
  try:
    top = decodeCbor(raw)
  except CborError as e:
    return err("descriptor is not strict CBOR: " & e.msg)
  if not validateDeterministic(raw):
    return err("descriptor is not deterministic CBOR")
  let r = checkClosedMap(top, ["interfaces", "primary"], "descriptor")
  if r.isErr:
    return err(r.error)
  let ifacesVal = top.mapGet("interfaces")
  if ifacesVal.kind != ckArray:
    return err("descriptor interfaces is not an array")
  if ifacesVal.items.len > MaxCallSurfaceInterfaces:
    return err("descriptor has more than " & $MaxCallSurfaceInterfaces & " interfaces")

  var surface = CallSurface(primary: Opt.none(CallSurfaceContract), interfaces: @[])
  var roots: seq[seq[byte]]
  var ifaceNamespaces: seq[string]
  var primaryMeths: seq[string]
  var allMeths: Table[string, string]

  if not top.mapGet("primary").isNil:
    let rc = validateContract(
      top.mapGet("primary"), roleConcrete, moduleName, roots, ifaceNamespaces
    )
    if rc.isErr:
      return err(rc.error)
    let c = rc.get
    surface.primary = Opt.some(c)
    for m in c.methodNames:
      if m in allMeths:
        return err("bare method name " & m & " collides across contracts")
      allMeths[m] = c.namespace
  for iv in ifacesVal.items:
    let rc = validateContract(iv, roleInterface, moduleName, roots, ifaceNamespaces)
    if rc.isErr:
      return err(rc.error)
    let c = rc.get
    surface.interfaces.add(c)
    for m in c.methodNames:
      if m in allMeths:
        return err("bare method name " & m & " collides across contracts")
      allMeths[m] = c.namespace

  if surface.primary.isNone and surface.interfaces.len == 0:
    return err("descriptor must contain a primary or at least one interface")

  # reserved common-schema bare method name (the well-known
  # `logos.schema` method)
  for m in allMeths.keys:
    if m == "schema":
      return err("reserved bare method name: schema")

  # _implements must exactly match the interface entry set
  if surface.primary.isSome:
    let rulesR = parseCddl(surface.primary.get.document)
    if rulesR.isErr:
      return err("contract document: " & rulesR.error)
    let rules = rulesR.get
    if hasRule(rules, "_implements"):
      let declaredR = implementsValues(rules)
      if declaredR.isErr:
        return err(declaredR.error)
      let declared = declaredR.get
      if declared.len != surface.interfaces.len:
        return err("_implements does not match the interface set")
      for ns in declared:
        if ns notin ifaceNamespaces:
          return err("_implements names unknown interface " & ns)
    elif surface.interfaces.len != 0:
      return err("descriptor has interfaces but no _implements")

  # canonical interface order: namespace UTF-8 bytes, then schema-root bytes
  for i in 1 ..< surface.interfaces.len:
    let a = surface.interfaces[i - 1]
    let b = surface.interfaces[i]
    if a.namespace > b.namespace or
        (a.namespace == b.namespace and cmpBytes(a.schemaRoot, b.schemaRoot) > 0):
      return err("interfaces not in canonical order")
  ok(surface)

## ---------------------------------------------------------------------------
## Loading (RUNTIME §2.1/§2.2, §3.6)

## Artifact acceptance (RUNTIME §3.6) runs BEFORE executable mapping.
## Phase 2 wires the interface; Phase 5 supplies the real authorization
## source, at which point this hook is invoked from init.
proc checkAcceptance(
    acceptance: Opt[ArtifactAcceptance], path: string, expectedName: string
): Result[void, string] =
  if acceptance.isSome:
    let a = acceptance.get
    let digest = a.verify(path)
    if digest.isErr:
      return err("artifact verification failed: " & digest.error)
    let auth = a.authorize(path, expectedName)
    if auth.isErr:
      return err("module execution not authorized: " & auth.error)
  ok()

proc initImpl(
  path: string, expectedName: string, isProvider: bool
): Result[SharedModule, string]

proc init*(
    path: string, expectedName: string, isProvider: bool
): Result[SharedModule, string] =
  ## Load a native module under known-name resolution. All internal
  ## failures (including schema-parse exceptions) are returned as error
  ## Results so callers in a `raises: []` context can use this.
  try:
    initImpl(path, expectedName, isProvider)
  except Exception as e:
    err("module load failed: " & e.msg)

proc initImpl(
    path: string, expectedName: string, isProvider: bool
): Result[SharedModule, string] =
  ## Steps (RUNTIME §3.6): artifact acceptance (digest + execution
  ## authorization) BEFORE executable mapping, then dlopen, then
  ## known-name symbol resolution, then pre-init `logos_<module>_name()`
  ## check, then the mandatory lifecycle symbols, then — when the
  ## resolved input declares a provider contract — the provider symbols
  ## and full call-surface validation. No instance is created here.
  if not validModuleName(expectedName):
    return err("invalid module name: " & expectedName)
  if not fileExists(path):
    return err("Module file not found: " & path)

  # 5. executable mapping (artifact acceptance is a Phase-5 hook)
  let handle = dynlib.loadLib(path)
  if handle.isNil:
    return err("Failed to load module library: " & path)

  let prefix = "logos_" & expectedName & "_"

  # 6. known-name resolution: identity symbol, called pre-init
  let nameSym = dynlib.symAddr(handle, cstring(prefix & "name"))
  if nameSym.isNil:
    dynlib.unloadLib(handle)
    return err("Missing mandatory symbol: " & prefix & "name")
  let nameFn = cast[LogosNameFn](nameSym)
  let reported = $nameFn()
  if reported != expectedName:
    dynlib.unloadLib(handle)
    return err("module name mismatch: expected " & expectedName & ", got " & reported)

  # 7. mandatory lifecycle symbols
  let initSym = dynlib.symAddr(handle, cstring(prefix & "init"))
  let destroySym = dynlib.symAddr(handle, cstring(prefix & "destroy"))
  if initSym.isNil or destroySym.isNil:
    dynlib.unloadLib(handle)
    return err(
      "Missing mandatory lifecycle symbols: " & prefix & "init and/or " & prefix &
        "destroy"
    )

  var m = SharedModule(
    name: expectedName,
    path: path,
    handle: handle,
    nameFn: nameFn,
    initFn: cast[LogosInitFn](initSym),
    destroyFn: cast[LogosDestroyFn](destroySym),
    applyConfigurationFn: Opt.none(LogosApplyConfigurationFn),
    isProvider: isProvider,
    surface: CallSurface(primary: Opt.none(CallSurfaceContract), interfaces: @[]),
    instances: @[],
  )

  # optional standard ABI hook
  let applySym = dynlib.symAddr(handle, cstring(prefix & "apply_configuration"))
  if not applySym.isNil:
    m.applyConfigurationFn = Opt.some(cast[LogosApplyConfigurationFn](applySym))

  if isProvider:
    # 8. provider symbols (RUNTIME §1.2: required when the resolved
    # input declares at least one provider contract)
    let csSym = dynlib.symAddr(handle, cstring(prefix & "call_surface"))
    let freeSym = dynlib.symAddr(handle, cstring(prefix & "free"))
    let dispSym = dynlib.symAddr(handle, cstring(prefix & "dispatch"))
    if csSym.isNil or freeSym.isNil or dispSym.isNil:
      dynlib.unloadLib(handle)
      return err(
        "Missing mandatory provider symbols: " & prefix & "call_surface, " & prefix &
          "free, and/or " & prefix & "dispatch"
      )
    m.callSurfaceFn = cast[LogosCallSurfaceFn](csSym)
    m.freeFn = cast[LogosFreeFn](freeSym)
    m.dispatchFn = cast[LogosDispatchFn](dispSym)

    # 9. call-surface validation (INTERFACE §2.6, RUNTIME §2.4):
    # parse, resolve, recompute every schema root, compare with the
    # claimed commitments — before registration
    var outLen: csize_t
    let rawPtr = m.callSurfaceFn(addr outLen)
    if rawPtr.isNil or outLen == 0:
      dynlib.unloadLib(handle)
      return err("call_surface returned null or zero length")
    var raw = newSeq[byte](outLen)
    copyMem(addr raw[0], rawPtr, outLen)
    let surface = validateCallSurface(raw, expectedName)
    if surface.isErr:
      dynlib.unloadLib(handle)
      return err("invalid call surface: " & surface.error)
    m.surface = surface.get
  ok(m)

## ---------------------------------------------------------------------------
## Per-instance lifecycle (INTERFACE §2.6, RUNTIME §8.1)

proc initInstance*(
    m: var SharedModule,
    rcBinding: ptr LogosRuntimeControlBinding,
    publish: LogosPublishFn,
    publishUserData: pointer,
    stateDir: string,
    configCbor: seq[byte],
): Result[LogosModuleContext, string] =
  ## Create one module instance: build the versioned initialization
  ## input, set *out_context = NULL, invoke _init, and reject any
  ## result/context combination that violates the ABI.
  if rcBinding.isNil:
    return err("runtime_control binding must be non-null")
  if rcBinding.vtable.isNil:
    return err("runtime_control vtable must be non-null")
  if rcBinding.state.isNil:
    return err("runtime_control state must be non-null")
  if rcBinding.vtable.abiVersion != LOGOS_RUNTIME_CONTROL_VTABLE_ABI_VERSION:
    return err("unsupported runtime_control vtable version")
  if rcBinding.vtable.structSize < sizeof(LogosRuntimeControlVtable).csize_t:
    return err("runtime_control vtable too small")
  if rcBinding.vtable.call.isNil or rcBinding.vtable.releaseResponse.isNil or
      rcBinding.vtable.subscribe.isNil or rcBinding.vtable.unsubscribe.isNil or
      rcBinding.vtable.materializeRoute.isNil:
    return err("runtime_control vtable has a null required operation")
  var surfaceDeclaresEvents = false
  if m.surface.primary.isSome and m.surface.primary.get.hasEvents:
    surfaceDeclaresEvents = true
  for c in m.surface.interfaces:
    if c.hasEvents:
      surfaceDeclaresEvents = true
  if surfaceDeclaresEvents and publish.isNil:
    return err("call surface declares events; publish callback must be non-null")

  var inst = ModuleInstance(
    context: nil,
    destroyed: false,
    rcBinding: rcBinding,
    publish: publish,
    publishUserData: publishUserData,
    stateDir: stateDir,
    configCbor: configCbor,
  )
  var input = LogosModuleInitInput(
    abiVersion: LOGOS_MODULE_INIT_ABI_VERSION,
    structSize: sizeof(LogosModuleInitInput).csize_t,
    runtimeControl: rcBinding,
    publishUserData: publishUserData,
    publish: publish,
    stateDir: if stateDir.len > 0: stateDir.cstring else: nil,
    configurationCbor:
      if configCbor.len > 0:
        cast[ptr uint8](addr configCbor[0])
      else:
        nil,
    configurationCborLen: configCbor.len.csize_t,
  )
  var ctx: LogosModuleContext
  ctx = nil
  let res = m.initFn(addr input, addr ctx)
  if res.code == LOGOS_OK:
    if ctx.isNil:
      return err("init succeeded with a null context")
    inst.context = ctx
    m.instances.add(inst)
    ok(ctx)
  else:
    if not ctx.isNil:
      return err("init failed with a non-null context")
    # no _destroy for a failed initialization (RUNTIME §8.1)
    err(
      "init failed: code " & $res.code &
        (if res.message != nil: " (" & $res.message & ")" else: "")
    )

proc destroyInstance*(
    m: var SharedModule, ctx: LogosModuleContext
): Result[void, string] =
  ## Pass the context exactly once to _destroy (RUNTIME §2.2).
  for idx in 0 ..< m.instances.len:
    if m.instances[idx].context == ctx:
      if m.instances[idx].destroyed:
        return err("context already destroyed")
      m.destroyFn(ctx)
      m.instances[idx].destroyed = true
      return ok()
  err("unknown or foreign context")

proc liveInstances*(m: SharedModule): int =
  for i in m.instances:
    if not i.destroyed:
      inc(result)

## ---------------------------------------------------------------------------
## Dispatch (INTERFACE §2.6/§2.7)

proc dispatch*(
    m: SharedModule, ctx: LogosModuleContext, meth: string, params: openArray[byte]
): Result[seq[byte], string] =
  ## Generic deterministic-CBOR dispatch through _dispatch.
  if not m.isProvider:
    return err("module declares no provider contract")
  var respPtr: ptr uint8
  var respLen: csize_t
  # caller preconditions: *out = NULL, len = 0
  respPtr = nil
  respLen = 0
  let reqPtr =
    if params.len > 0:
      cast[ptr uint8](addr params[0])
    else:
      nil
  let res = m.dispatchFn(
    ctx, meth.cstring, reqPtr, params.len.csize_t, addr respPtr, addr respLen
  )
  if res.code == LOGOS_OK:
    if respPtr.isNil or respLen == 0:
      return err("dispatch succeeded with a null or empty response")
    var resp = newSeq[byte](respLen)
    copyMem(addr resp[0], respPtr, respLen)
    # ownership transferred to the caller; release with the same
    # module instance's _free
    m.freeFn(ctx, respPtr)
    ok(resp)
  else:
    # a failed dispatch transfers no output ownership; do not
    # dereference or free the written pointer
    if not respPtr.isNil or respLen != 0:
      return err("dispatch failed with non-null output")
    err(
      "dispatch failed: code " & $res.code &
        (if res.message != nil: " (" & $res.message & ")" else: "")
    )
