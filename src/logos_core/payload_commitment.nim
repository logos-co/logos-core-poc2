# src/logos_core/payload_commitment.nim
# Payload commitments per LOGOS-MODULE-TRANSPORT §4.1 and the commitment
# model §7/§8/§9.2/§9.3.
#
# A `logos.transport.payload-commitment` binds a schema-typed payload value
# to two 32-byte roots:
#   - schema_subtree_root: the schema-subtree-root identity of the named
#     declaration (request/response/event type) under which the value is
#     decoded (commitment model §9.2, `logos.schema.node`).
#   - value_root: the root of the transmitted value under that exact subtree
#     (hash profile, `logos.value.root`).
#
# This module computes both from a schema document, a named declaration, and
# a deterministic-CBOR value. It builds the normalized value tree (commitment
# model §9.3) by decoding the value under the declaration's canonical schema
# node, threading the nearest-named-declaration identity and the
# schema-node-path so that every node carries the correct schema identity
# (named subtree root, structural subtree root, or leaf hash).

import results
import std/tables
import ./cbor_profile, ./commitment, ./hash_profile, ./value_tree, ./transport

## The nearest named declaration's identity (kind + qualified name), threaded
## through the value-tree decode for structural/leaf identity computation.
type DeclInfo = object
  kindStr*: string
  qualifiedName*: string

## A schema-node-path segment (commitment model §9.2).
func fieldSegment(name: string): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("field")), (cborValue(uint64(1)), cborValue(name))
  )

func listElementSegment(): CborValue =
  cborMap((cborValue(uint64(0)), cborValue("list-element")))

func tuplePositionSegment(pos: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("tuple-position")),
    (cborValue(uint64(1)), cborValue(pos)),
  )

func choiceArmSegment(arm: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("choice-arm")),
    (cborValue(uint64(1)), cborValue(arm)),
  )

## The canonical node-kind tag (the integer key `0` of a schema node).
func nodeKindTag(n: CborValue): string =
  for (k, v) in n.entries:
    if k.kind == ckUint and k.u == 0:
      return v.s
  ""

func isLeafNode(n: CborValue): bool =
  let t = nodeKindTag(n)
  t == "primitive" or t == "literal" or t == "local-reference" or
    t == "imported-reference"

## The schema identity (subtree root or leaf hash) of one canonical schema
## node under the nearest named declaration `di` at path `path`
## (commitment model §9.2).
proc nodeIdentity(node: CborValue, di: DeclInfo, path: seq[CborValue]): seq[byte] =
  if isLeafNode(node):
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("schema-leaf")),
      (cborValue(uint64(1)), cborValue(CommitmentModelRevision)),
      (cborValue(uint64(2)), cborValue(di.kindStr)),
      (cborValue(uint64(3)), cborValue(di.qualifiedName)),
      (cborValue(uint64(4)), cborArray(path)),
      (cborValue(uint64(5)), node),
    )
    hashPayload(DomainSchemaLeaf, payload)
  else:
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("schema-structural-node")),
      (cborValue(uint64(1)), cborValue(CommitmentModelRevision)),
      (cborValue(uint64(2)), cborValue(di.kindStr)),
      (cborValue(uint64(3)), cborValue(di.qualifiedName)),
      (cborValue(uint64(4)), cborArray(path)),
      (cborValue(uint64(5)), node),
    )
    hashPayload(DomainSchemaNode, payload)

# ============================================================================
# Value-tree decoding
# ============================================================================

func scalarMatchesLiteral(lit: CborValue, val: CborValue): bool =
  ## True if the decoded value equals a literal scalar.
  if lit.kind != val.kind:
    return false
  case lit.kind
  of ckBool:
    lit.b == val.b
  of ckUint:
    lit.u == val.u
  of ckNint:
    lit.n == val.n
  of ckText:
    lit.s == val.s
  of ckBytes:
    cmpBytes(lit.by, val.by) == 0
  else:
    false

## Whether a value belongs to a choice arm (POC selection: literal and
## primitive arms; the full structural selection plan is out of scope).
func armAcceptsValue(arm: CborValue, val: CborValue): bool =
  case nodeKindTag(arm)
  of "literal":
    scalarMatchesLiteral(arm.intMapGet(2), val)
  of "primitive":
    case arm.intMapGet(1).s
    of "bool":
      val.kind == ckBool
    of "uint8", "uint16", "uint32", "uint64":
      val.kind == ckUint
    of "int8", "int16", "int32", "int64":
      val.kind == ckNint
    of "tstr":
      val.kind == ckText
    of "bstr":
      val.kind == ckBytes
    else:
      false
  else:
    false

proc decodeScalar(
    node: CborValue, val: CborValue, di: DeclInfo, path: seq[CborValue]
): Result[VNode, string] =
  ## Decode a scalar under a primitive or literal schema node.
  let kind = node.intMapGet(1).s
  let identity = nodeIdentity(node, di, path)
  # the value's scalar kind MUST match the schema scalar kind (commitment
  # model §9.1); a mismatch is a decode error, not a representable value
  case kind
  of "bool":
    if val.kind != ckBool:
      return err("expected bool, got " & $val.kind)
  of "uint8", "uint16", "uint32", "uint64":
    if val.kind != ckUint:
      return err("expected uint, got " & $val.kind)
  of "int8", "int16", "int32", "int64":
    if val.kind != ckNint:
      return err("expected int, got " & $val.kind)
  of "tstr":
    if val.kind != ckText:
      return err("expected tstr, got " & $val.kind)
  of "bstr":
    if val.kind != ckBytes:
      return err("expected bstr, got " & $val.kind)
  else:
    discard
  # size constraint (field 2) applies only to tstr/bstr PRIMITIVES; a literal
  # node's field 2 is the scalar data, not a constraint map
  if nodeKindTag(node) == "primitive":
    for (k, v) in node.entries:
      if k.kind == ckUint and k.u == 2:
        let lo = v.intMapGet(1).u
        let hi = v.intMapGet(2).u
        let dataLen =
          if kind == "tstr":
            uint64(val.s.len)
          elif kind == "bstr":
            uint64(val.by.len)
          else:
            uint64(0)
        if dataLen < lo or dataLen > hi:
          return err("value violates size constraint")
  if nodeKindTag(node) == "literal":
    let lit = node.intMapGet(2)
    if not scalarMatchesLiteral(lit, val):
      return err("value does not match the literal")
  ok(VNode(kind: vkScalar, subtree: identity, scalarKind: kind, scalarData: val))

proc findDecl(ctx: SchemaCtx, name: string): Result[LocalDecl, string] =
  for d in ctx.decls:
    if d.name == name:
      return ok(d)
  err("declaration not found: " & name)

proc decodeValueTree(
    node: CborValue, ctx: SchemaCtx, val: CborValue, di: DeclInfo, path: seq[CborValue]
): Result[VNode, string] =
  ## Decode a deterministic-CBOR value under one canonical schema node,
  ## producing the normalized value tree node (commitment model §9.3). The
  ## returned node's `subtree` is the effective schema identity under which
  ## the value is decoded (structural subtree root or leaf hash for anonymous
  ## nodes). Named declarations are handled by `decodeNamedDecl`, which
  ## overrides the top node's subtree with the named subtree root.
  let tag = nodeKindTag(node)
  case tag
  of "primitive", "literal":
    decodeScalar(node, val, di, path)
  of "map":
    let identity = nodeIdentity(node, di, path)
    if val.kind != ckMap:
      return err("expected a map value")
    var fields: seq[CborValue]
    for item in node.intMapGet(1).items:
      fields.add(item)
    var mapFields: seq[VNode] = @[]
    for f in fields:
      let fieldName = f.intMapGet(0).s
      let optional = f.intMapGet(1).b
      let fieldNode = f.intMapGet(2)
      let fieldPath = path & @[fieldSegment(fieldName)]
      let fieldId = nodeIdentity(fieldNode, di, fieldPath)
      var haveVal = false
      var fieldVal: CborValue
      for (k, v) in val.entries:
        if k.kind == ckText and k.s == fieldName:
          haveVal = true
          fieldVal = v
          break
      if haveVal:
        let child = ?decodeValueTree(fieldNode, ctx, fieldVal, di, fieldPath)
        mapFields.add(
          VNode(
            kind: vkField, subtree: fieldId, fieldName: fieldName, fieldChild: child
          )
        )
      else:
        if not optional:
          return err("missing required field '" & fieldName & "'")
        mapFields.add(VNode(kind: vkAbsent, subtree: fieldId, absentName: fieldName))
    # reject unknown fields (closed map)
    for (k, _) in val.entries:
      if k.kind == ckText:
        var known = false
        for f in fields:
          if f.intMapGet(0).s == k.s:
            known = true
            break
        if not known:
          return err("unknown field '" & k.s & "'")
    ok(VNode(kind: vkMap, subtree: identity, mapFields: mapFields))
  of "list":
    let identity = nodeIdentity(node, di, path)
    if val.kind != ckArray:
      return err("expected an array value")
    let elemNode = node.intMapGet(1)
    let elemPath = path & @[listElementSegment()]
    let elemId = nodeIdentity(elemNode, di, elemPath)
    var elems: seq[VNode] = @[]
    var i = uint64(0)
    for e in val.items:
      let child = ?decodeValueTree(elemNode, ctx, e, di, elemPath)
      elems.add(
        VNode(kind: vkListElement, subtree: elemId, elemIndex: i, elemChild: child)
      )
      inc i
    var elemKind = ""
    if isLeafNode(elemNode):
      elemKind = elemNode.intMapGet(1).s
    ok(
      VNode(
        kind: vkList,
        subtree: identity,
        listElements: elems,
        elemKind: elemKind,
        elemSubtree: elemId,
      )
    )
  of "tuple":
    let identity = nodeIdentity(node, di, path)
    if val.kind != ckArray:
      return err("expected an array value")
    var positions: seq[CborValue]
    for item in node.intMapGet(1).items:
      positions.add(item)
    if uint64(val.items.len) != uint64(positions.len):
      return err("tuple length mismatch")
    var elems: seq[VNode] = @[]
    var pos = uint64(0)
    for e in val.items:
      let posNode = positions[pos]
      let posPath = path & @[tuplePositionSegment(pos)]
      let posId = nodeIdentity(posNode, di, posPath)
      let child = ?decodeValueTree(posNode, ctx, e, di, posPath)
      elems.add(
        VNode(kind: vkTupleElement, subtree: posId, tuplePos: pos, tupleChild: child)
      )
      inc pos
    ok(VNode(kind: vkTuple, subtree: identity, tupleElements: elems))
  of "choice":
    let identity = nodeIdentity(node, di, path)
    var arms: seq[CborValue]
    for item in node.intMapGet(1).items:
      arms.add(item)
    var selected = -1
    for ai in 0 ..< arms.len:
      if armAcceptsValue(arms[ai], val):
        if selected >= 0:
          return err("value matches more than one choice arm")
        selected = ai
    if selected < 0:
      return err("value matches no choice arm")
    let armNode = arms[selected]
    let armPath = path & @[choiceArmSegment(uint64(selected))]
    let armId = nodeIdentity(armNode, di, armPath)
    let child = ?decodeValueTree(armNode, ctx, val, di, armPath)
    ok(
      VNode(
        kind: vkChoice,
        subtree: identity,
        armIndex: uint64(selected),
        armSubtree: armId,
        armChild: child,
      )
    )
  of "local-reference":
    # Resolve to the referenced declaration; the value is decoded under that
    # declaration's body (no reference-value wrapper; the effective subtree
    # is the referenced declaration's named subtree root).
    let refName = node.intMapGet(1).s
    let rd = ?findDecl(ctx, refName)
    let refDi = DeclInfo(kindStr: kindFor(rd.kind), qualifiedName: refName)
    let refBody = declBody(ctx, rd)
    let refSub = namedSubtreeRootOf(ctx, rd)
    let top = ?decodeValueTree(refBody, ctx, val, refDi, @[])
    top.subtree = refSub
    ok(top)
  of "imported-reference":
    # Resolve to the referenced declaration in the separately supplied
    # supporting document or the pinned common schema; the value is decoded
    # under that declaration's body (the effective subtree is the referenced
    # declaration's named subtree root) — COMMITMENT MODEL §9.1/§9.3, I1.
    let imp = node.intMapGet(1)
    let schemaRoot = imp.intMapGet(0)
    let subtreeRoot = imp.intMapGet(1)
    if schemaRoot.kind != ckBytes or subtreeRoot.kind != ckBytes:
      return err("imported-reference schema-import is not a byte-string pair")
    # A supporting-document reference: match the document's schema root, then
    # look up the declaration by its exact subtree root.
    for sr in ctx.supporting:
      if schemaRoot.by == sr.schemaRoot:
        let sctx = sr.ctx[]
        for d in sctx.decls:
          if sr.declRoots[d.name] == subtreeRoot.by:
            let refDi = DeclInfo(kindStr: kindFor(d.kind), qualifiedName: d.name)
            let refBody = declBody(sctx, d)
            let top = ?decodeValueTree(refBody, sctx, val, refDi, @[])
            top.subtree = subtreeRoot.by
            return ok(top)
    # A pinned common-schema reference: match the common schema root, then
    # look up the declaration by its exact subtree root.
    if schemaRoot.by == hexBytes(CommonSchemaRootHex):
      let commonCtx = ?buildCommonContext()
      for d in commonCtx.decls:
        let dSub = namedSubtreeRootOf(commonCtx, d)
        if dSub == subtreeRoot.by:
          let refDi = DeclInfo(kindStr: kindFor(d.kind), qualifiedName: d.name)
          let refBody = declBody(commonCtx, d)
          let top = ?decodeValueTree(refBody, commonCtx, val, refDi, @[])
          top.subtree = subtreeRoot.by
          return ok(top)
    err("unresolved imported reference")
  else:
    err("unknown schema node kind '" & tag & "'")

proc decodeNamedDecl*(
    cddl: string, ctx: SchemaCtx, declName: string, val: CborValue
): Result[VNode, string] =
  ## Decode a value under a named declaration; the top node's subtree is the
  ## declaration's named subtree root (commitment model §9.2/§9.3).
  let d = ?findDecl(ctx, declName)
  let di = DeclInfo(kindStr: kindFor(d.kind), qualifiedName: declName)
  let body = declBody(ctx, d)
  let namedSub = namedSubtreeRootOf(ctx, d)
  let top = ?decodeValueTree(body, ctx, val, di, @[])
  top.subtree = namedSub
  ok(top)

# ============================================================================
# Payload commitment
# ============================================================================

proc computePayloadCommitment*(
    cddl: string,
    declName: string,
    value: CborValue,
    supporting: openArray[(string, string)] = @[],
): Result[PayloadCommitment, string] =
  ## Compute the two-root payload commitment for a schema-typed value under a
  ## named declaration (TRANSPORT §4.1), resolving references against the
  ## separately supplied supporting schemas (INTERFACE §2.6/§5.3, I1).
  var supRefs: seq[SupportingRef]
  for (ns, doc) in supporting:
    let refR = buildSupportingRef(doc)
    if refR.isErr:
      return err(refR.error)
    supRefs.add(refR.get)
  let model = ?buildSchemaModel(cddl, supRefs)
  let schemaRoot = hashPayload(DomainSchemaRoot, model)
  let ctx = ?buildContext(cddl, supRefs)
  let d = ?findDecl(ctx, declName)
  let subtree = namedSubtreeRootOf(ctx, d)
  let top = ?decodeNamedDecl(cddl, ctx, declName, value)
  computeValueDigest(top, schemaRoot)
  let valueRoot = computeValueRoot(schemaRoot, subtree, top)
  ok(PayloadCommitment(schemaSubtreeRoot: subtree, valueRoot: valueRoot))
