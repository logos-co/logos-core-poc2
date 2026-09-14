## LOGOS-MODULE-COMMITMENT-MODEL (2026-08)
##
## Logos domain interpretation over the cdCDDLe canonical CDDL schema model:
## schema-role detection, namespace derivation, declaration classification,
## method pairing, schema-node translation, canonical ordering, and the
## structural choice selection plan. Produces the `normalized-schema-root`
## object (spec §9.1), schema identity payloads (spec §9.2), and the
## semantic value tree (spec §9.3).
##
## Conformance: Appendix A construction vector (storage schema),
## Appendix B schema-and-value-tree vector (demo schema).

import cdcddle
import cbor_profile
import hash_profile
import value_tree
import results
import std/tables
import std/strutils

const
  CommitmentModelRevision = hash_profile.CommitmentModelRevision
  DomainSchemaRoot = hash_profile.DomainSchemaRoot
  DomainSchemaNode = hash_profile.DomainSchemaNode
  DomainSchemaLeaf = hash_profile.DomainSchemaLeaf
  DomainSchemaReference = hash_profile.DomainSchemaReference

  KindType* = "type"
  KindMethod* = "method"
  KindMethodRequest* = "method-request"
  KindMethodResponse* = "method-response"
  KindEvent* = "event"

type SchemaError* = object of Exception

proc schemaError*(msg: string): ref SchemaError =
  newException(SchemaError, msg)

type
  SchemaRole* = enum
    roleConcrete
    roleInterface
    roleSupporting

  DeclKind* = enum
    dkType
    dkMethod
    dkRequest
    dkResponse
    dkEvent

  LocalDecl* = object
    name*: string
    kind*: DeclKind
    body: CddlNode # cdCDDLe AST body

  ## One separately supplied supporting schema, resolved for reference
  ## translation (INTERFACE §2.6, §5.3). Carries the supporting document's
  ## recomputed schema root and each declaration's exact subtree root so a
  ## reference to it translates to an `imported-reference` node (COMMITMENT
  ## MODEL §9.1: schema-import = { schema-root, schema-subtree-root }). The
  ## context is a `ref` so this type can be defined before `SchemaCtx` (which
  ## in turn holds a `seq[SupportingRef]`).
  SupportingRef* = object
    schemaRoot*: seq[byte]
    declRoots*: Table[string, seq[byte]] # qualified name -> subtree root
    ctx*: ref SchemaCtx # the document's context (for value decode under refs)

  SchemaCtx* = object
    role*: SchemaRole
    namespace*: string
    decls*: seq[LocalDecl]
    declByName: Table[string, int]
    supporting*: seq[SupportingRef] # separately supplied supporting schemas

## ---------------------------------------------------------------------------
## Prelude and pinned common-schema registry (COMMITMENT-MODEL §5)

proc preludeScalarKind*(name: string): string =
  ## Logos prelude fixed-width integer aliases; "" if not a prelude alias.
  case name
  of "uint8":
    result = "uint8"
  of "uint16":
    result = "uint16"
  of "uint32":
    result = "uint32"
  of "uint64":
    result = "uint64"
  of "int8":
    result = "int8"
  of "int16":
    result = "int16"
  of "int32":
    result = "int32"
  of "int64":
    result = "int64"
  else:
    result = ""

type CommonEntry = object
  name: string
  root: seq[byte]

const CommonSchemaRootHex* =
  "7e0236018aed522455dfbdba19f81fd67a050a61f2a05cb8d1027eda35107ca6"

proc hexVal(c: char): int =
  case c
  of '0' .. '9':
    ord(c) - ord('0')
  of 'a' .. 'f':
    ord(c) - ord('a') + 10
  of 'A' .. 'F':
    ord(c) - ord('A') + 10
  else:
    -1

proc hexBytes*(h: string): seq[byte] =
  for i in countUp(0, h.len - 1, 2):
    let hi = hexVal(h[i])
    let lo = hexVal(h[i + 1])
    if hi < 0 or lo < 0:
      raise schemaError("bad hex digit in " & h)
    result.add(byte(hi * 16 + lo))

const CommonRegistry*: seq[CommonEntry] = @[
  CommonEntry(
    name: "logos.error_code",
    root: hexBytes("f0efecb7f5f270919523d00dd977e5c0ca04b429e022a1a66856353831fd76a7"),
  ),
  CommonEntry(
    name: "logos.error_detail",
    root: hexBytes("a6a0bed0a560ed0499a7e1d4708741e0b6dce32f379cdbbf29d74637cb0ea3ff"),
  ),
  CommonEntry(
    name: "logos.invalid_params_detail",
    root: hexBytes("4a8b55144d4f00f42c19ffd90cb9c4173388c1ec00bafcf71df79b32a14163d9"),
  ),
  CommonEntry(
    name: "logos.invalid_params_path_segment",
    root: hexBytes("6fc94679ad488099793d930fec7eaf2fb200a0e117c85c28188f8f2458b0d451"),
  ),
  CommonEntry(
    name: "logos.invalid_params_reason",
    root: hexBytes("c55a3c96f6306a438e357b35d7cedbeca054ceb68cc1188eb38b036da7ac6816"),
  ),
  CommonEntry(
    name: "logos.schema",
    root: hexBytes("8997083caebf86ede43a744e16ac7018eacc3a51e4e603af4ef0ed8bd14158c3"),
  ),
  CommonEntry(
    name: "logos.schema_commitment",
    root: hexBytes("b9adbab7aea835c64a3b89031c45d7868d21069be0943f0581d527234812d064"),
  ),
  CommonEntry(
    name: "logos.schema_request",
    root: hexBytes("b6f1788290d01092fba9e956e405ecd6bd5c5584f64ceeab8a60df92a52ae585"),
  ),
  CommonEntry(
    name: "logos.schema_response",
    root: hexBytes("3fde7207bddb450e0a7583953b7db2cf393382cc971a67ca8394bfa6b1896e18"),
  ),
]

## The pinned common schema's declarations (COMMITMENT MODEL §5): the well-known
## common types in the `logos` namespace. A reference to one of these translates
## to an imported-reference node carrying the common schema root and the
## declaration's subtree root; the value is decoded under the declaration's body
## (this document). MUST NOT be re-declared in a module's primary document.
const CommonSchemaCddl* = """
logos.schema_commitment = {
    commitment_model: "logos.commitment-model.2026-08",
    schema_root: bstr .size 32,
    hash_profile: "logos.hash-profile.2026-08.choice-index",
    hash_suite: "logos.hash-suite.blake3-256",
}
"""

## ---------------------------------------------------------------------------
## Construction (spec §3.1)

proc isMetadataName(n: string): bool =
  n == "_module" or n == "_interface" or n == "_implements"

proc deriveNamespace(names: openArray[string]): string =
  ## longest common dot-segment prefix, a proper prefix of every name
  if names.len == 0:
    raise schemaError("no local declarations for namespace derivation")
  var segs: seq[seq[string]]
  for n in names:
    segs.add(n.split('.'))
  var common = 0
  let first = segs[0]
  while common < first.len:
    var ok = true
    for s in segs:
      if common >= s.len or s[common] != first[common]:
        ok = false
        break
    if not ok:
      break
    inc(common)
  for s in segs:
    if s.len <= common:
      raise schemaError("schema namespace is not a proper prefix of " & $s)
  result = first[0 ..< common].join(".")

proc classify(name: string, role: SchemaRole): DeclKind =
  if role == roleSupporting:
    result = dkType
  elif name.endsWith("_request"):
    result = dkRequest
  elif name.endsWith("_response"):
    result = dkResponse
  elif name.endsWith("_event"):
    result = dkEvent
  else:
    result = dkType

proc buildContextImpl(cddl: string): SchemaCtx =
  let rules = parseCddlImpl(cddl)
  # role detection
  var role = roleSupporting
  var hasModule = false
  for r in rules:
    if r.name == "_module":
      role = roleConcrete
      hasModule = true
    elif r.name == "_interface":
      role = roleInterface
  if hasModule and role == roleInterface:
    raise schemaError("both _module and _interface present")
  # local (non-metadata) declarations
  var names: seq[string]
  var bodies: Table[string, CddlNode]
  for r in rules:
    if isMetadataName(r.name):
      continue
    names.add(r.name)
    bodies[r.name] = r.body
  let ns = deriveNamespace(names)
  for n in names:
    if not n.startsWith(ns & "."):
      raise schemaError("declaration " & n & " is not in the primary namespace")
  # classification + method pairing
  var decls: seq[LocalDecl]
  var requests, responses: Table[string, bool]
  for n in names:
    case classify(n, role)
    of dkRequest:
      requests[n] = true
      decls.add(LocalDecl(name: n, kind: dkRequest, body: bodies[n]))
    of dkResponse:
      responses[n] = true
      decls.add(LocalDecl(name: n, kind: dkResponse, body: bodies[n]))
    else:
      decls.add(LocalDecl(name: n, kind: classify(n, role), body: bodies[n]))
  # pair requests with responses (base name = request name minus "_request")
  for reqName in requests.keys:
    let base = reqName[0 ..< reqName.len - "_request".len]
    let respName = base & "_response"
    if respName notin responses:
      raise schemaError("request " & reqName & " has no matching response")
    decls.add(
      LocalDecl(name: base, kind: dkMethod, body: CddlNode(kind: nkRef, name: base))
    )
  for respName in responses.keys:
    let base = respName[0 ..< respName.len - "_response".len]
    let reqName = base & "_request"
    if reqName notin requests:
      raise schemaError("response " & respName & " has no matching request")
  # index
  result = SchemaCtx(role: role, namespace: ns, decls: decls)
  for i, d in decls:
    if d.name in result.declByName:
      raise schemaError("duplicate declaration: " & d.name)
    result.declByName[d.name] = i

## Build the Logos domain context for a schema document. Errors are returned
## as a Result (never raised) so a malformed module-supplied document cannot
## abort the runtime process (K10).
proc buildContext*(cddl: string): Result[SchemaCtx, string] =
  try:
    ok(buildContextImpl(cddl))
  except CddlError as e:
    err(e.msg)
  except SchemaError as e:
    err(e.msg)

## Build the Logos domain context for a primary document together with its
## separately supplied supporting schemas (INTERFACE §2.6/§5.3). References
## to a supporting schema's declarations translate to `imported-reference`
## nodes carrying that document's schema root and the declaration subtree
## root; references to the pinned common schema translate to
## `imported-reference` nodes carrying the common schema root. The primary
## namespace is derived from the primary document's own declarations only —
## inlined supporting or re-declared common declarations no longer collapse
## it (I1).
proc buildContext*(
    primary: string, supporting: openArray[SupportingRef]
): Result[SchemaCtx, string] =
  try:
    var ctx = buildContextImpl(primary)
    ctx.supporting = @supporting
    ok(ctx)
  except CddlError as e:
    err(e.msg)
  except SchemaError as e:
    err(e.msg)

## Build a context for the pinned common schema (COMMITMENT MODEL §5). The
## common schema is a fixed registry of well-known types addressed by full
## name (e.g. `logos.schema_commitment`), not a primary/supporting document,
## so the usual namespace-derivation + prefix validation does not apply (a
## single-declaration registry cannot yield a proper dot-segment prefix). The
## context is used only for value decode: looking up a declaration's body and
## subtree root by its exact name.
proc buildCommonContext*(): Result[SchemaCtx, string] =
  try:
    let rules = parseCddlImpl(CommonSchemaCddl)
    var decls: seq[LocalDecl]
    for r in rules:
      if isMetadataName(r.name):
        continue
      decls.add(LocalDecl(name: r.name, kind: dkType, body: r.body))
    var ctx = SchemaCtx(role: roleSupporting, namespace: "logos", decls: decls)
    for i, d in decls:
      ctx.declByName[d.name] = i
    ok(ctx)
  except CddlError as e:
    err(e.msg)

## ---------------------------------------------------------------------------
## Schema-node translation (spec §3.1, §9.1)

proc primitiveNode(kind: string, size: CborValue, hasSize: bool): CborValue =
  if hasSize:
    cborMap(
      (cborValue(uint64(0)), cborValue("primitive")),
      (cborValue(uint64(1)), cborValue(kind)),
      (cborValue(uint64(2)), size),
    )
  else:
    cborMap(
      (cborValue(uint64(0)), cborValue("primitive")),
      (cborValue(uint64(1)), cborValue(kind)),
    )

proc literalNode(kind: string, val: CborValue): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("literal")),
    (cborValue(uint64(1)), cborValue(kind)),
    (cborValue(uint64(2)), val),
  )

proc localRefNode(name: string): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("local-reference")),
    (cborValue(uint64(1)), cborValue(name)),
  )

## One `imported-reference` node (COMMITMENT MODEL §9.1):
##   imported-reference-schema = { 0: "imported-reference", 1: schema-import }
##   schema-import = { 0: schema-root, 1: schema-subtree-root }
## `schemaRoot` is the complete referenced schema's root (the pinned common
## schema root for a common-schema reference, or the supporting document's
## recomputed root for a supporting-schema reference); `subtreeRoot` is the
## exact referenced declaration's subtree root.
proc importedRefNode(schemaRoot, subtreeRoot: seq[byte]): CborValue =
  let imp = cborMap(
    (cborValue(uint64(0)), cborValue(schemaRoot)),
    (cborValue(uint64(1)), cborValue(subtreeRoot)),
  )
  cborMap(
    (cborValue(uint64(0)), cborValue("imported-reference")), (cborValue(uint64(1)), imp)
  )

## One `imported-reference` node for a pinned common-schema reference: the
## schema root is the fixed common schema root (COMMITMENT MODEL §5).
proc commonRefNode(subtreeRoot: seq[byte]): CborValue =
  importedRefNode(hexBytes(CommonSchemaRootHex), subtreeRoot)

proc sizeController(n: CddlNode): (uint64, uint64) =
  ## parse a .size controller into (min, max)
  case n.kind
  of nkUint:
    result = (n.u, n.u)
  of nkRange:
    let lo = n.lo.u
    let hi = n.hi.u
    if lo > hi:
      raise schemaError("size constraint minimum exceeds maximum")
    result = (lo, hi)
  else:
    raise schemaError("invalid size controller")

proc translateNode*(n: CddlNode, ctx: SchemaCtx): CborValue =
  case n.kind
  of nkPrimitive:
    case n.name
    of "bool":
      primitiveNode("bool", CborValue(), false)
    of "tstr":
      primitiveNode("tstr", CborValue(), false)
    of "bstr":
      primitiveNode("bstr", CborValue(), false)
    of "uint":
      raise schemaError("bare uint is not a Logos scalar kind; use a prelude alias")
    else:
      raise schemaError("unsupported primitive: " & n.name)
  of nkUint:
    literalNode("uint64", cborValue(n.u))
  of nkNint:
    literalNode("int64", cborValue(n.n))
  of nkBool:
    literalNode("bool", cborValue(n.b))
  of nkTstr:
    if "\0" in n.s:
      raise schemaError("tstr literal contains U+0000")
    literalNode("tstr", cborValue(n.s))
  of nkBstr:
    raise schemaError("byte-string literals are invalid in schema declaration bodies")
  of nkRef:
    let pk = preludeScalarKind(n.name)
    if pk != "":
      primitiveNode(pk, CborValue(), false)
    elif n.name in ctx.declByName:
      localRefNode(n.name)
    else:
      # A reference to a separately supplied supporting schema's declaration
      # becomes an imported reference carrying that document's schema root
      # and the exact declaration subtree root (COMMITMENT MODEL §3.1 step 5,
      # §9.1). Checked before the pinned registry: a supporting schema is
      # an explicit construction input, the pinned common schema is the
      # fallback for well-known common names.
      for sr in ctx.supporting:
        if n.name in sr.declRoots:
          return importedRefNode(sr.schemaRoot, sr.declRoots[n.name])
      # A reference to a pinned common-schema declaration becomes an imported
      # reference carrying the common schema root and the declaration subtree
      # root (COMMITMENT MODEL §5: both roots MUST match the pinned registry).
      for e in CommonRegistry:
        if e.name == n.name:
          return commonRefNode(e.root)
      raise schemaError("unresolved reference: " & n.name)
  of nkMap:
    var fields: seq[(string, bool, CddlNode)]
    for m in n.members:
      if not m.hasKey:
        raise schemaError("map member without a key")
      fields.add((m.key, m.occ == occOptional, m.ty))
    # sort by canonical field name
    let nf = fields.len
    for i in 1 ..< nf:
      let key = fields[i]
      var j = i - 1
      while j >= 0 and fields[j][0] > key[0]:
        fields[j + 1] = fields[j]
        dec(j)
      fields[j + 1] = key
    var recs: seq[CborValue]
    for (fname, opt, ty) in fields:
      recs.add(
        cborMap(
          (cborValue(uint64(0)), cborValue(fname)),
          (cborValue(uint64(1)), cborValue(opt)),
          (cborValue(uint64(2)), translateNode(ty, ctx)),
        )
      )
    cborMap(
      (cborValue(uint64(0)), cborValue("map")), (cborValue(uint64(1)), cborArray(recs))
    )
  of nkArray:
    if n.members.len == 1 and n.members[0].occ == occUnbounded:
      cborMap(
        (cborValue(uint64(0)), cborValue("list")),
        (cborValue(uint64(1)), translateNode(n.members[0].ty, ctx)),
      )
    else:
      if n.members.len > 0 and n.members[0].occ != occRequired:
        raise schemaError("invalid tuple member occurrence")
      var recs: seq[CborValue]
      for m in n.members:
        recs.add(translateNode(m.ty, ctx))
      cborMap(
        (cborValue(uint64(0)), cborValue("tuple")),
        (cborValue(uint64(1)), cborArray(recs)),
      )
  of nkChoice:
    var arms: seq[CborValue]
    for a in n.alts:
      arms.add(translateNode(a, ctx))
    # sort arms by deterministic-CBOR encoding of the canonical arm node
    var encs: seq[seq[byte]]
    for a in arms:
      encs.add(encodeCbor(a))
    let na = arms.len
    for i in 1 ..< na:
      let keyEnc = encs[i]
      let keyArm = arms[i]
      var j = i - 1
      while j >= 0 and cmpBytes(encs[j], keyEnc) > 0:
        encs[j + 1] = encs[j]
        arms[j + 1] = arms[j]
        dec(j)
      encs[j + 1] = keyEnc
      arms[j + 1] = keyArm
    for i in 1 ..< na:
      if cmpBytes(encs[i], encs[i - 1]) == 0:
        raise schemaError("duplicate choice arms")
    cborMap(
      (cborValue(uint64(0)), cborValue("choice")),
      (cborValue(uint64(1)), cborArray(arms)),
    )
  of nkRange:
    raise schemaError("integer ranges are not Logos schema nodes")
  of nkSize:
    let t = n.target
    var primKind = ""
    if t.kind == nkPrimitive:
      case t.name
      of "tstr":
        primKind = "tstr"
      of "bstr":
        primKind = "bstr"
      else:
        raise schemaError("size constraint on unsupported primitive")
    else:
      raise schemaError("size constraint on non-primitive")
    let (lo, hi) = sizeController(n.controller)
    let sc = cborMap(
      (cborValue(uint64(0)), cborValue("size")),
      (cborValue(uint64(1)), cborValue(lo)),
      (cborValue(uint64(2)), cborValue(hi)),
    )
    primitiveNode(primKind, sc, true)

## ---------------------------------------------------------------------------
## Structural choice selection plan (spec §3.1)

type PlanCtx = object
  ctx: SchemaCtx
  visited: seq[string]

proc followRef(node: CddlNode, pc: var PlanCtx, res: var CddlNode): bool =
  ## resolve a local reference with cycle detection; true if resolved
  if node.kind != nkRef:
    res = node
    return true
  if node.name in pc.visited:
    return false
  if node.name notin pc.ctx.declByName:
    return false
  pc.visited.add(node.name)
  let idx = pc.ctx.declByName[node.name]
  let r = followRef(pc.ctx.decls[idx].body, pc, res)
  pc.visited.setLen(pc.visited.len - 1)
  r

proc armAcceptsMajor(node: CddlNode, major: int, pc: var PlanCtx): bool =
  case node.kind
  of nkPrimitive:
    case node.name
    of "bool":
      major == 7
    of "tstr":
      major == 3
    of "bstr":
      major == 2
    of "uint":
      major == 0
    else:
      false
  of nkUint:
    major == 0
  of nkNint:
    major == 0 or major == 1
  of nkBool:
    major == 7
  of nkTstr:
    major == 3
  of nkBstr:
    major == 2
  of nkMap:
    major == 5
  of nkArray:
    major == 4
  of nkChoice:
    for a in node.alts:
      if armAcceptsMajor(a, major, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsMajor(r, major, pc)
    else:
      false
  of nkRange:
    false
  of nkSize:
    # a .size control wraps a primitive; the accepted major type is that of
    # the target primitive
    armAcceptsMajor(node.target, major, pc)

proc armAcceptsScalar(node: CddlNode, val: CborValue, pc: var PlanCtx): bool =
  case node.kind
  of nkPrimitive:
    case node.name
    of "bool":
      val.kind == ckBool
    of "uint":
      val.kind == ckUint
    of "tstr":
      val.kind == ckText and "\0" notin val.s
    of "bstr":
      val.kind == ckBytes
    else:
      false
  of nkUint:
    # exact literal value, not just the CBOR major kind (spec §3.1: distinct
    # integer-literal choices are valid and must be discriminated)
    val.kind == ckUint and val.u == node.u
  of nkNint:
    val.kind == ckNint and val.n == node.n
  of nkBool:
    val.kind == ckBool and val.b == node.b
  of nkTstr:
    val.kind == ckText and val.s == node.s
  of nkBstr:
    val.kind == ckBytes and val.by == node.by
  of nkChoice:
    for a in node.alts:
      if armAcceptsScalar(a, val, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsScalar(r, val, pc)
    else:
      false
  of nkArray, nkMap, nkRange:
    false
  of nkSize:
    armAcceptsScalar(node.target, val, pc)

proc armAcceptsOtherScalar(node: CddlNode, pc: var PlanCtx): bool =
  case node.kind
  of nkPrimitive:
    node.name == "bool" or node.name == "uint" or node.name == "tstr" or
      node.name == "bstr"
  of nkUint, nkNint, nkBool, nkTstr, nkBstr:
    false
  of nkChoice:
    for a in node.alts:
      if armAcceptsOtherScalar(a, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsOtherScalar(r, pc)
    else:
      false
  of nkArray, nkMap, nkRange:
    false
  of nkSize:
    armAcceptsOtherScalar(node.target, pc)

proc armAcceptsNonScalar(node: CddlNode, pc: var PlanCtx): bool =
  case node.kind
  of nkMap, nkArray:
    true
  of nkChoice:
    for a in node.alts:
      if armAcceptsNonScalar(a, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsNonScalar(r, pc)
    else:
      false
  else:
    false

proc armAcceptsTupleLen(node: CddlNode, n: int, pc: var PlanCtx): bool =
  case node.kind
  of nkArray:
    n == node.members.len and (n == 0 or node.members[0].occ == occRequired)
  of nkChoice:
    for a in node.alts:
      if armAcceptsTupleLen(a, n, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsTupleLen(r, n, pc)
    else:
      false
  else:
    false

proc armAcceptsOtherTupleLen(node: CddlNode, pc: var PlanCtx): bool =
  case node.kind
  of nkArray:
    node.members.len == 1 and node.members[0].occ == occUnbounded
  of nkChoice:
    for a in node.alts:
      if armAcceptsOtherTupleLen(a, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsOtherTupleLen(r, pc)
    else:
      false
  else:
    false

proc armAcceptsNonArray(node: CddlNode, pc: var PlanCtx): bool =
  case node.kind
  of nkPrimitive, nkUint, nkNint, nkBool, nkTstr, nkBstr, nkMap, nkSize:
    true
  of nkChoice:
    for a in node.alts:
      if armAcceptsNonArray(a, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsNonArray(r, pc)
    else:
      false
  else:
    false

proc mapFieldsOf(
    node: CddlNode, pc: var PlanCtx, res: var seq[(string, bool, CddlNode)]
) =
  case node.kind
  of nkMap:
    for m in node.members:
      res.add((m.key, m.occ == occOptional, m.ty))
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      mapFieldsOf(r, pc, res)
  else:
    discard

proc armAcceptsFieldAbsent(node: CddlNode, field: string, pc: var PlanCtx): bool =
  case node.kind
  of nkMap:
    for m in node.members:
      if m.key == field:
        return m.occ == occOptional
    true # closed map: field not defined -> absent
  of nkChoice:
    for a in node.alts:
      if armAcceptsFieldAbsent(a, field, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsFieldAbsent(r, field, pc)
    else:
      false
  else:
    false

proc armAcceptsFieldPresent(node: CddlNode, field: string, pc: var PlanCtx): bool =
  case node.kind
  of nkMap:
    for m in node.members:
      if m.key == field:
        return true
    false # closed map
  of nkChoice:
    for a in node.alts:
      if armAcceptsFieldPresent(a, field, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsFieldPresent(r, field, pc)
    else:
      false
  else:
    false

proc armAcceptsFieldValue(
    node: CddlNode, field: string, val: CborValue, pc: var PlanCtx
): bool =
  case node.kind
  of nkMap:
    for m in node.members:
      if m.key == field:
        return armAcceptsScalar(m.ty, val, pc)
    false
  of nkChoice:
    for a in node.alts:
      if armAcceptsFieldValue(a, field, val, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsFieldValue(r, field, val, pc)
    else:
      false
  else:
    false

proc armAcceptsFieldOtherValue(node: CddlNode, field: string, pc: var PlanCtx): bool =
  case node.kind
  of nkMap:
    for m in node.members:
      if m.key == field:
        return armAcceptsOtherScalar(m.ty, pc) or armAcceptsNonScalar(m.ty, pc)
    false
  of nkChoice:
    for a in node.alts:
      if armAcceptsFieldOtherValue(a, field, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsFieldOtherValue(r, field, pc)
    else:
      false
  else:
    false

proc armAcceptsNonMap(node: CddlNode, pc: var PlanCtx): bool =
  case node.kind
  of nkPrimitive, nkUint, nkNint, nkBool, nkTstr, nkBstr, nkArray, nkSize:
    true
  of nkChoice:
    for a in node.alts:
      if armAcceptsNonMap(a, pc):
        return true
    false
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      armAcceptsNonMap(r, pc)
    else:
      false
  else:
    false

proc collectLiterals(node: CddlNode, pc: var PlanCtx, res: var seq[CborValue]) =
  ## exact scalar literal values reachable from a node
  case node.kind
  of nkUint:
    res.add(cborValue(node.u))
  of nkNint:
    res.add(cborValue(node.n))
  of nkBool:
    res.add(cborValue(node.b))
  of nkTstr:
    res.add(cborValue(node.s))
  of nkBstr:
    res.add(cborValue(node.by))
  of nkChoice:
    for a in node.alts:
      collectLiterals(a, pc, res)
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      collectLiterals(r, pc, res)
  else:
    discard

proc tupleArity(node: CddlNode, pc: var PlanCtx, res: var int): bool =
  ## fixed tuple arity, if the node is a fixed tuple
  case node.kind
  of nkArray:
    if node.members.len > 0 and node.members[0].occ == occRequired:
      res = node.members.len
      result = true
  of nkChoice:
    for a in node.alts:
      var n: int
      if tupleArity(a, pc, n):
        if res != -1 and n != res:
          return false
        res = n
        result = true
  of nkRef:
    var r: CddlNode

    if followRef(node, pc, r):
      result = tupleArity(r, pc, res)
    else:
      result = false
  else:
    result = false

proc testProgress*(
    outcomes: openArray[seq[int]], cands: seq[int], stack: var seq[seq[int]]
): bool =
  ## A structural test makes progress only when every outcome retains a strict
  ## subset of the candidate set AND at least one outcome is non-empty.
  ## All-empty outcomes make no progress: a non-productive reference cycle
  ## yields no finite structural outcome and cannot distinguish a choice arm
  ## (spec §3.1 normative table: `A / B` with `A = B`, `B = A` is Invalid).
  var anyNonEmpty = false
  for o in outcomes:
    if o.len == cands.len:
      return false
    if o.len > 0:
      anyNonEmpty = true
  if not anyNonEmpty:
    return false
  for o in outcomes:
    if (0 < o.len) and (o.len < cands.len):
      stack.add(o)
  true

proc checkSelectionPlan*(arms: seq[CddlNode], ctx: SchemaCtx): bool =
  ## spec §3.1: a finite decision tree proving no value matches >1 arm.
  var pc = PlanCtx(ctx: ctx)
  type Cand = seq[int]
  var stack: seq[Cand]
  var all: Cand
  for i in arms.low() .. arms.high():
    all.add(i)
  stack.add(all)
  while stack.len > 0:
    let cands = stack.pop()
    if cands.len <= 1:
      continue
    var progress = false
    var outcomes: seq[Cand]
    # test 1: CBOR major type
    for major in 0 .. 7:
      var r: Cand
      for i in cands:
        if armAcceptsMajor(arms[i], major, pc):
          r.add(i)
      outcomes.add(r)
    if testProgress(outcomes, cands, stack):
      progress = true
    if progress:
      continue
    # test 2: exact scalar literal
    var lits: seq[CborValue]
    for i in cands:
      collectLiterals(arms[i], pc, lits)
    outcomes.setLen(0)
    for L in lits:
      var seen = false
      for e in lits:
        if encodeCbor(e) == encodeCbor(L):
          seen = true
          break
      if seen:
        var r: Cand
        for i in cands:
          if armAcceptsScalar(arms[i], L, pc):
            r.add(i)
        outcomes.add(r)
        break
    var rOther: Cand
    for i in cands:
      if armAcceptsOtherScalar(arms[i], pc):
        rOther.add(i)
    outcomes.add(rOther)
    var rNA: Cand
    for i in cands:
      if armAcceptsNonScalar(arms[i], pc):
        rNA.add(i)
    outcomes.add(rNA)
    if testProgress(outcomes, cands, stack):
      progress = true
    if progress:
      continue
    # test 3: fixed tuple length
    var lens: seq[int]
    for i in cands:
      var n = -1
      if tupleArity(arms[i], pc, n):
        if n notin lens:
          lens.add(n)
    outcomes.setLen(0)
    for n in lens:
      var r: Cand
      for i in cands:
        if armAcceptsTupleLen(arms[i], n, pc):
          r.add(i)
      outcomes.add(r)
    rOther.setLen(0)
    for i in cands:
      if armAcceptsOtherTupleLen(arms[i], pc):
        rOther.add(i)
    outcomes.add(rOther)
    rNA.setLen(0)
    for i in cands:
      if armAcceptsNonArray(arms[i], pc):
        rNA.add(i)
    outcomes.add(rNA)
    if testProgress(outcomes, cands, stack):
      progress = true
    if progress:
      continue
    # tests 4+5: closed-map field literal / presence
    var fields: seq[string]
    for i in cands:
      var fl: seq[(string, bool, CddlNode)]
      mapFieldsOf(arms[i], pc, fl)
      for f in fl:
        if f[0] notin fields:
          fields.add(f[0])
    let nf = fields.len
    for i in 1 ..< nf:
      let key = fields[i]
      var j = i - 1
      while j >= 0 and fields[j] > key:
        fields[j + 1] = fields[j]
        dec(j)
      fields[j + 1] = key
    for field in fields:
      # test 4: field literal values
      var flits: seq[CborValue]
      for i in cands:
        var fl: seq[(string, bool, CddlNode)]
        mapFieldsOf(arms[i], pc, fl)
        for f in fl:
          if f[0] == field:
            collectLiterals(f[2], pc, flits)
      var madeProgress = false
      if flits.len > 0:
        outcomes.setLen(0)
        for L in flits:
          var r: Cand
          for i in cands:
            if armAcceptsFieldValue(arms[i], field, L, pc):
              r.add(i)
          outcomes.add(r)
        rOther.setLen(0)
        for i in cands:
          if armAcceptsFieldOtherValue(arms[i], field, pc):
            rOther.add(i)
        outcomes.add(rOther)
        rNA.setLen(0)
        for i in cands:
          if armAcceptsFieldAbsent(arms[i], field, pc) or armAcceptsNonMap(arms[i], pc):
            rNA.add(i)
        outcomes.add(rNA)
        madeProgress = testProgress(outcomes, cands, stack)
      if madeProgress:
        progress = true
        break
      # test 5: field presence
      outcomes.setLen(0)
      var rPresent: Cand
      for i in cands:
        if armAcceptsFieldPresent(arms[i], field, pc):
          rPresent.add(i)
      outcomes.add(rPresent)
      var rAbsent: Cand
      for i in cands:
        if armAcceptsFieldAbsent(arms[i], field, pc):
          rAbsent.add(i)
      outcomes.add(rAbsent)
      rNA.setLen(0)
      for i in cands:
        if armAcceptsNonMap(arms[i], pc):
          rNA.add(i)
      outcomes.add(rNA)
      if testProgress(outcomes, cands, stack):
        progress = true
        break
    if progress:
      continue
    return false # no test made progress with >1 candidate
  true

## ---------------------------------------------------------------------------
## Normalized schema root (spec §9.1)

proc kindFor*(k: DeclKind): string =
  case k
  of dkType: "type"
  of dkMethod: "method"
  of dkRequest: "method-request"
  of dkResponse: "method-response"
  of dkEvent: "event"

proc validateChoices(n: CddlNode, ctx: SchemaCtx, declName: string) =
  ## validate all choice selection plans under a declaration body
  case n.kind
  of nkChoice:
    if not checkSelectionPlan(n.alts, ctx):
      raise schemaError("invalid choice: " & declName)
    for a in n.alts:
      validateChoices(a, ctx, declName)
  of nkArray, nkMap:
    for m in n.members:
      validateChoices(m.ty, ctx, declName)
  of nkSize:
    validateChoices(n.target, ctx, declName)
    validateChoices(n.controller, ctx, declName)
  of nkRange:
    validateChoices(n.lo, ctx, declName)
    validateChoices(n.hi, ctx, declName)
  else:
    discard

proc methodNode(reqName, respName: string): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("method")),
    (cborValue(uint64(1)), cborValue(reqName)),
    (cborValue(uint64(2)), cborValue(respName)),
  )

proc sortDecls(decls: var seq[LocalDecl]) =
  ## insertion sort by qualified name
  let nd = decls.len
  for i in 1 ..< nd:
    let key = decls[i]
    var j = i - 1
    while j >= 0 and decls[j].name > key.name:
      decls[j + 1] = decls[j]
      dec(j)
    decls[j + 1] = key

proc buildSchemaModelImpl(ctx: SchemaCtx): CborValue =
  ## produce the normalized-schema-root object (spec §9.1)
  var sorted = ctx.decls
  sortDecls(sorted)
  var decls: seq[CborValue]
  for d in sorted:
    let body =
      case d.kind
      of dkMethod:
        # pair the request/response
        let reqName = d.name & "_request"
        let respName = d.name & "_response"
        methodNode(reqName, respName)
      else:
        # validate choice selection plans
        validateChoices(d.body, ctx, d.name)
        translateNode(d.body, ctx)
    let kindStr = kindFor(d.kind)
    decls.add(
      cborMap(
        (cborValue(uint64(0)), cborValue(kindStr)),
        (cborValue(uint64(1)), cborValue(d.name)),
        (cborValue(uint64(2)), body),
      )
    )
  cborMap(
    (cborValue(uint64(0)), cborValue("schema-root")),
    (cborValue(uint64(1)), cborValue(CommitmentModelRevision)),
    (cborValue(uint64(2)), cborValue(ctx.namespace)),
    (cborValue(uint64(3)), cborArray(decls)),
    (cborValue(uint64(4)), cborArray()),
  )

## Produce the normalized-schema-root object (spec §9.1). Errors are returned
## as a Result (never raised).
proc buildSchemaModel*(cddl: string): Result[CborValue, string] =
  try:
    ok(buildSchemaModelImpl(buildContextImpl(cddl)))
  except CddlError as e:
    err(e.msg)
  except SchemaError as e:
    err(e.msg)

## Produce the normalized-schema-root object for a primary document together
## with its separately supplied supporting schemas (INTERFACE §2.6/§5.3).
## References to supporting declarations translate to imported-reference
## nodes; the primary namespace is derived from the primary document's own
## declarations only (I1).
proc buildSchemaModel*(
    primary: string, supporting: openArray[SupportingRef]
): Result[CborValue, string] =
  try:
    var ctx = buildContextImpl(primary)
    ctx.supporting = @supporting
    ok(buildSchemaModelImpl(ctx))
  except CddlError as e:
    err(e.msg)
  except SchemaError as e:
    err(e.msg)

## ---------------------------------------------------------------------------
## Named schema subtree root (commitment model §9.1/§9.2)
## ---------------------------------------------------------------------------

proc declBody*(ctx: SchemaCtx, d: LocalDecl): CborValue =
  ## The canonical `schema-declaration-body` for one declaration.
  case d.kind
  of dkMethod:
    methodNode(d.name & "_request", d.name & "_response")
  else:
    translateNode(d.body, ctx)

proc namedSubtreeRootOf*(ctx: SchemaCtx, d: LocalDecl): seq[byte] =
  ## The `logos.schema.node` digest of the `schema-node-payload` for one named
  ## declaration, computed from an existing context (commitment model §9.2).
  let body = declBody(ctx, d)
  let kindStr = kindFor(d.kind)
  let payload = cborMap(
    (cborValue(uint64(0)), cborValue("schema-node")),
    (cborValue(uint64(1)), cborValue(CommitmentModelRevision)),
    (cborValue(uint64(2)), cborValue(d.name)),
    (cborValue(uint64(3)), cborValue(kindStr)),
    (cborValue(uint64(4)), body),
  )
  hashPayload(DomainSchemaNode, payload)

proc namedSubtreeRoot*(cddl: string, qualifiedName: string): Result[seq[byte], string] =
  ## The `logos.schema.node` digest of the `schema-node-payload` for one named
  ## declaration (commitment model §9.2). This is the schema-subtree-root
  ## identity used in payload commitments.
  let ctx = ?buildContext(cddl)
  for d in ctx.decls:
    if d.name == qualifiedName:
      return ok(namedSubtreeRootOf(ctx, d))
  err("declaration not found: " & qualifiedName)

## Build a `SupportingRef` from a supporting schema document's CDDL
## (INTERFACE §2.6/§5.3). Computes the document's recomputed schema root and
## each declaration's exact subtree root so references to it translate to
## imported-reference nodes. The document MUST be a supporting schema (no
## `_module`/`_interface` marker). Errors are returned as a Result (never
## raised).
proc buildSupportingRef*(cddl: string): Result[SupportingRef, string] =
  try:
    let ctx = buildContextImpl(cddl)
    if ctx.role != roleSupporting:
      return err("supporting document must be a supporting schema")
    let model = buildSchemaModelImpl(ctx)
    let schemaRoot = hashPayload(DomainSchemaRoot, model)
    var declRoots: Table[string, seq[byte]]
    for d in ctx.decls:
      declRoots[d.name] = namedSubtreeRootOf(ctx, d)
    let pctx = new(SchemaCtx)
    pctx[] = ctx
    ok(SupportingRef(schemaRoot: schemaRoot, declRoots: declRoots, ctx: pctx))
  except CddlError as e:
    err(e.msg)
  except SchemaError as e:
    err(e.msg)

proc schemaRootOf*(cddl: string): Result[seq[byte], string] =
  ## The whole-schema root (the `logos.schema.root` digest of the
  ## normalized-schema-root object).
  let model = ?buildSchemaModel(cddl)
  ok(hashPayload(DomainSchemaRoot, model))

proc methodDecls*(cddl: string, methodName: string): Result[(string, string), string] =
  ## Resolve a bare method name under a contract to its request and response
  ## declaration names (commitment model §9.1: a method is a request/response
  ## declaration pair). Returns err if either declaration is absent.
  let reqDecl = methodName & "_request"
  let respDecl = methodName & "_response"
  let ctx = ?buildContext(cddl)
  var haveReq = false
  var haveResp = false
  for d in ctx.decls:
    if d.name == reqDecl:
      haveReq = true
    elif d.name == respDecl:
      haveResp = true
  if not haveReq:
    return err("method " & methodName & " not found in contract")
  if not haveResp:
    return err("method " & methodName & " has no response declaration")
  ok((reqDecl, respDecl))
