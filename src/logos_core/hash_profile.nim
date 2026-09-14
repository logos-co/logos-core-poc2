## LOGOS-MODULE-HASH-PROFILE (2026-08.choice-index)
##
## Physical hash profile: domain-separated structured hash inputs, the
## mandatory BLAKE3-256 suite, canonical packing/chunking/branching rules,
## and the deterministic-CBOR value payload shapes. Converts a semantic
## value tree (value_tree.VNode) into physical payloads and computes the
## 32-byte digests (value roots, subtree identities, proof steps).
##
## Conformance: Appendix A schema-root vector (796-byte hash input),
## Appendix B.1 packed-scalar-list boundary, B.2 byte-string chunk boundary,
## B.3 branch boundary.

import blake3
import cbor_profile
import value_tree

const
  CommitmentModelRevision* = "logos.commitment-model.2026-08"
  HashProfileId* = "logos.hash-profile.2026-08.choice-index"
  HashSuiteId* = "logos.hash-suite.blake3-256"

  # Domain tags (Section 5, Section 7.2)
  DomainSchemaRoot* = "logos.schema.root"
  DomainSchemaNode* = "logos.schema.node"
  DomainSchemaLeaf* = "logos.schema.leaf"
  DomainSchemaReference* = "logos.schema.reference"

  DomainValueRoot* = "logos.value.root"
  DomainValueMap* = "logos.value.map"
  DomainValueField* = "logos.value.field"
  DomainValueAbsent* = "logos.value.absent"
  DomainValueList* = "logos.value.list"
  DomainValueListChunk* = "logos.value.list-chunk"
  DomainValuePackedScalar* = "logos.value.packed-scalar-list-chunk"
  DomainValueTuple* = "logos.value.tuple"
  DomainValueTupleElement* = "logos.value.tuple-element"
  DomainValueChoice* = "logos.value.choice"
  DomainValueScalar* = "logos.value.scalar"
  DomainValueBstr* = "logos.value.bstr"
  DomainValueBstrDirect* = "logos.value.bstr-direct"
  DomainValueBstrChunk* = "logos.value.bstr-chunk"
  DomainValueTstr* = "logos.value.tstr"
  DomainValueTstrDirect* = "logos.value.tstr-direct"
  DomainValueTstrChunk* = "logos.value.tstr-chunk"
  DomainValueReference* = "logos.value.reference"
  DomainValueBranch* = "logos.value.branch"

  # Canonical chunk sizes (Section 4)
  MaxDirectStringBytes* = 4096
  MaxDirectChildren* = 256
  PackedChunkSize* = 256
  ListChunkSize* = 256
  StringChunkSize* = 4096

  # Packable scalar kinds (Section 4)
  PackableScalarKinds* =
    @["bool", "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64"]

proc isPackableScalar*(kind: string): bool =
  kind in PackableScalarKinds

## ---------------------------------------------------------------------------
## Canonical hash input (Section 7.1)

proc hashInput*(domainTag: string, payload: CborValue): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue(domainTag)),
    (cborValue(uint64(1)), cborValue(HashProfileId)),
    (cborValue(uint64(2)), cborValue(HashSuiteId)),
    (cborValue(uint64(3)), cborValue(CommitmentModelRevision)),
    (cborValue(uint64(4)), payload),
  )

proc hashPayload*(domainTag: string, payload: CborValue): seq[byte] =
  ## mandatory BLAKE3-256 over the deterministic-CBOR hash input
  let d = blake3_256(encodeCbor(hashInput(domainTag, payload)))
  @d

proc strToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len:
    result[i] = byte(ord(s[i]))

## ---------------------------------------------------------------------------
## Child records and labels (Section 7.3)

proc fieldLabel*(name: string): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("field")), (cborValue(uint64(1)), cborValue(name))
  )

proc indexLabel*(i: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("index")), (cborValue(uint64(1)), cborValue(i))
  )

proc indexRangeLabel*(start, count: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("index-range")),
    (cborValue(uint64(1)), cborValue(start)),
    (cborValue(uint64(2)), cborValue(count)),
  )

proc tupleLabel*(pos: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("tuple-position")),
    (cborValue(uint64(1)), cborValue(pos)),
  )

proc choiceLabel*(arm: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("choice-arm")),
    (cborValue(uint64(1)), cborValue(arm)),
  )

proc byteRangeLabel*(start, count: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("byte-range")),
    (cborValue(uint64(1)), cborValue(start)),
    (cborValue(uint64(2)), cborValue(count)),
  )

proc branchLabel*(start, count: uint64): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue("branch")),
    (cborValue(uint64(1)), cborValue(start)),
    (cborValue(uint64(2)), cborValue(count)),
  )

proc rootChildRecord*(nodeKind: string, digest, subtree: seq[byte]): CborValue =
  cborMap(
    (cborValue(uint64(0)), cborValue(nodeKind)),
    (cborValue(uint64(1)), cborValue(digest)),
    (cborValue(uint64(2)), cborValue(subtree)),
  )

proc childRecord*(
    label: CborValue, nodeKind: string, digest, subtree: seq[byte]
): CborValue =
  cborMap(
    (cborValue(uint64(0)), label),
    (cborValue(uint64(1)), cborValue(nodeKind)),
    (cborValue(uint64(2)), cborValue(digest)),
    (cborValue(uint64(3)), cborValue(subtree)),
  )

## ---------------------------------------------------------------------------
## Branch construction (Section 5)

proc buildBranches*(
    records: openArray[CborValue],
    schemaRoot, parentSubtree: seq[byte],
    parentKind: string,
): seq[CborValue] =
  ## group an ordered child-record sequence into the canonical branch tree;
  ## returns the final-level records for the collection payload
  if records.len <= MaxDirectChildren:
    result = @records
    return
  var branchRecs: seq[CborValue]
  var i = uint64(0)
  while i < uint64(records.len):
    let count = min(uint64(PackedChunkSize), uint64(records.len) - i)
    var children: seq[CborValue]
    for j in i ..< i + count:
      children.add(records[j])
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("branch")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(parentSubtree)),
      (cborValue(uint64(3)), cborValue(parentKind)),
      (cborValue(uint64(4)), cborValue(i)),
      (cborValue(uint64(5)), cborValue(count)),
      (cborValue(uint64(6)), cborArray(children)),
    )
    let digest = hashPayload(DomainValueBranch, payload)
    branchRecs.add(childRecord(branchLabel(i, count), "branch", digest, parentSubtree))
    i += count
  result = buildBranches(branchRecs, schemaRoot, parentSubtree, parentKind)

## ---------------------------------------------------------------------------
## Physical node kind (Section 5)

proc scalarIsString(node: VNode): (bool, bool) =
  ## (isString, isBstr)
  (node.scalarKind == "tstr" or node.scalarKind == "bstr", node.scalarKind == "bstr")

proc physicalNodeKind*(node: VNode): string =
  case node.kind
  of vkMap:
    "map"
  of vkField:
    "field"
  of vkAbsent:
    "absent"
  of vkList:
    "list"
  of vkTuple:
    "tuple"
  of vkChoice:
    "choice"
  of vkReference:
    "reference-value"
  of vkScalar:
    let (isStr, isBstr) = scalarIsString(node)
    if not isStr:
      "scalar"
    else:
      let dataLen =
        if node.scalarData.kind == ckBytes:
          uint64(node.scalarData.by.len)
        else:
          uint64(node.scalarData.s.len)
      if dataLen <= uint64(MaxDirectStringBytes):
        if isBstr: "bstr-direct" else: "tstr-direct"
      else:
        if isBstr: "bstr" else: "tstr"
  of vkListElement, vkTupleElement:
    # element wrappers are not directly committed; their child is
    raise newException(Exception, "element wrapper has no physical kind")

## ---------------------------------------------------------------------------
## Physical layout (Sections 4, 5, 7.4)

proc computeValueDigest*(node: VNode, schemaRoot: seq[byte]) =
  ## bottom-up: compute the physical payload digest for a value node;
  ## sets node.digest as a side effect
  case node.kind
  of vkScalar:
    let (isStr, isBstr) = scalarIsString(node)
    if not isStr:
      # bool / integer scalar
      let payload = cborMap(
        (cborValue(uint64(0)), cborValue("scalar")),
        (cborValue(uint64(1)), cborValue(schemaRoot)),
        (cborValue(uint64(2)), cborValue(node.subtree)),
        (cborValue(uint64(3)), cborValue(node.scalarKind)),
        (cborValue(uint64(4)), node.scalarData),
      )
      node.digest = hashPayload(DomainValueScalar, payload)
    else:
      let dataLen =
        if isBstr:
          uint64(node.scalarData.by.len)
        else:
          uint64(node.scalarData.s.len)
      if dataLen <= uint64(MaxDirectStringBytes):
        # direct string
        let payload = cborMap(
          (
            cborValue(uint64(0)),
            cborValue(if isBstr: "bstr-direct" else: "tstr-direct"),
          ),
          (cborValue(uint64(1)), cborValue(schemaRoot)),
          (cborValue(uint64(2)), cborValue(node.subtree)),
          (cborValue(uint64(3)), cborValue(dataLen)),
          (
            cborValue(uint64(4)),
            if isBstr:
              cborValue(node.scalarData.by)
            else:
              cborValue(node.scalarData.s),
          ),
        )
        node.digest = hashPayload(
          if isBstr: DomainValueBstrDirect else: DomainValueTstrDirect, payload
        )
      else:
        # chunked aggregate
        var bytes: seq[byte]
        if isBstr:
          bytes = node.scalarData.by
        else:
          bytes = strToBytes(node.scalarData.s)
        var chunks: seq[CborValue]
        var off = uint64(0)
        while off < uint64(bytes.len):
          let count = min(uint64(StringChunkSize), uint64(bytes.len) - off)
          let chunkBytes = bytes[off ..< off + count]
          let chunkPayload = cborMap(
            (
              cborValue(uint64(0)),
              cborValue(if isBstr: "bstr-chunk" else: "tstr-chunk"),
            ),
            (cborValue(uint64(1)), cborValue(schemaRoot)),
            (cborValue(uint64(2)), cborValue(node.subtree)),
            (cborValue(uint64(3)), cborValue(uint64(bytes.len))),
            (cborValue(uint64(4)), cborValue(off)),
            (cborValue(uint64(5)), cborValue(count)),
            (cborValue(uint64(6)), cborValue(chunkBytes)),
          )
          let chunkDigest = hashPayload(
            if isBstr: DomainValueBstrChunk else: DomainValueTstrChunk, chunkPayload
          )
          chunks.add(
            childRecord(
              byteRangeLabel(off, count),
              if isBstr: "bstr-chunk" else: "tstr-chunk",
              chunkDigest,
              node.subtree,
            )
          )
          off += count
        let records = buildBranches(
          chunks, schemaRoot, node.subtree, if isBstr: "bstr" else: "tstr"
        )
        let payload = cborMap(
          (cborValue(uint64(0)), cborValue(if isBstr: "bstr" else: "tstr")),
          (cborValue(uint64(1)), cborValue(schemaRoot)),
          (cborValue(uint64(2)), cborValue(node.subtree)),
          (cborValue(uint64(3)), cborValue(uint64(bytes.len))),
          (cborValue(uint64(4)), cborArray(records)),
        )
        node.digest =
          hashPayload(if isBstr: DomainValueBstr else: DomainValueTstr, payload)
  of vkField:
    computeValueDigest(node.fieldChild, schemaRoot)
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("field")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(node.fieldName)),
      (
        cborValue(uint64(4)),
        rootChildRecord(
          physicalNodeKind(node.fieldChild),
          node.fieldChild.digest,
          node.fieldChild.subtree,
        ),
      ),
    )
    node.digest = hashPayload(DomainValueField, payload)
  of vkAbsent:
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("absent")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(node.absentName)),
    )
    node.digest = hashPayload(DomainValueAbsent, payload)
  of vkMap:
    var records: seq[CborValue]
    for f in node.mapFields:
      case f.kind
      of vkField:
        computeValueDigest(f, schemaRoot)
        records.add(childRecord(fieldLabel(f.fieldName), "field", f.digest, f.subtree))
      of vkAbsent:
        computeValueDigest(f, schemaRoot)
        records.add(
          childRecord(fieldLabel(f.absentName), "absent", f.digest, f.subtree)
        )
      else:
        raise newException(Exception, "map field must be field or absent")
    let final = buildBranches(records, schemaRoot, node.subtree, "map")
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("map")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(uint64(node.mapFields.len))),
      (cborValue(uint64(4)), cborArray(final)),
    )
    node.digest = hashPayload(DomainValueMap, payload)
  of vkList:
    let length = uint64(node.listElements.len)
    var baseRecords: seq[CborValue]
    if node.elemKind != "" and node.elemKind in PackableScalarKinds:
      # packable scalar list
      if length <= uint64(PackedChunkSize):
        # direct element commitments
        for e in node.listElements:
          computeValueDigest(e.elemChild, schemaRoot)
          baseRecords.add(
            childRecord(
              indexLabel(e.elemIndex), "scalar", e.elemChild.digest, e.elemChild.subtree
            )
          )
      else:
        # packed scalar chunks of 256
        var i = uint64(0)
        while i < length:
          let count = min(uint64(PackedChunkSize), length - i)
          var values: seq[CborValue]
          for j in i ..< i + count:
            values.add(node.listElements[j].elemChild.scalarData)
          let chunkPayload = cborMap(
            (cborValue(uint64(0)), cborValue("packed-scalar-list-chunk")),
            (cborValue(uint64(1)), cborValue(schemaRoot)),
            (cborValue(uint64(2)), cborValue(node.subtree)),
            (cborValue(uint64(3)), cborValue(node.elemSubtree)),
            (cborValue(uint64(4)), cborValue(node.elemKind)),
            (cborValue(uint64(5)), cborValue(i)),
            (cborValue(uint64(6)), cborValue(count)),
            (cborValue(uint64(7)), cborArray(values)),
          )
          let chunkDigest = hashPayload(DomainValuePackedScalar, chunkPayload)
          baseRecords.add(
            childRecord(
              indexRangeLabel(i, count),
              "packed-scalar-list-chunk",
              chunkDigest,
              node.subtree,
            )
          )
          i += count
    else:
      # ordinary element commitments
      if length <= uint64(ListChunkSize):
        for e in node.listElements:
          computeValueDigest(e.elemChild, schemaRoot)
          baseRecords.add(
            childRecord(
              indexLabel(e.elemIndex),
              physicalNodeKind(e.elemChild),
              e.elemChild.digest,
              e.elemChild.subtree,
            )
          )
      else:
        # list chunks of 256 element records
        var i = uint64(0)
        while i < length:
          let count = min(uint64(ListChunkSize), length - i)
          var elemRecs: seq[CborValue]
          for j in i ..< i + count:
            let e = node.listElements[j]
            computeValueDigest(e.elemChild, schemaRoot)
            elemRecs.add(
              childRecord(
                indexLabel(e.elemIndex),
                physicalNodeKind(e.elemChild),
                e.elemChild.digest,
                e.elemChild.subtree,
              )
            )
          let chunkPayload = cborMap(
            (cborValue(uint64(0)), cborValue("list-chunk")),
            (cborValue(uint64(1)), cborValue(schemaRoot)),
            (cborValue(uint64(2)), cborValue(node.subtree)),
            (cborValue(uint64(3)), cborValue(node.elemSubtree)),
            (cborValue(uint64(4)), cborValue(i)),
            (cborValue(uint64(5)), cborValue(count)),
            (cborValue(uint64(6)), cborArray(elemRecs)),
          )
          let chunkDigest = hashPayload(DomainValueListChunk, chunkPayload)
          baseRecords.add(
            childRecord(
              indexRangeLabel(i, count), "list-chunk", chunkDigest, node.subtree
            )
          )
          i += count
    let final = buildBranches(baseRecords, schemaRoot, node.subtree, "list")
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("list")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(node.elemSubtree)),
      (cborValue(uint64(4)), cborValue(length)),
      (cborValue(uint64(5)), cborArray(final)),
    )
    node.digest = hashPayload(DomainValueList, payload)
  of vkTuple:
    var records: seq[CborValue]
    for e in node.tupleElements:
      # the tuple-element wrapper is not directly committed; its child is
      computeValueDigest(e.tupleChild, schemaRoot)
      # tuple-element payload (spec §7.4): commits to the element's schema
      # subtree identity, its zero-based position, and the child's physical
      # record
      let elemPayload = cborMap(
        (cborValue(uint64(0)), cborValue("tuple-element")),
        (cborValue(uint64(1)), cborValue(schemaRoot)),
        (cborValue(uint64(2)), cborValue(e.subtree)),
        (cborValue(uint64(3)), cborValue(e.tuplePos)),
        (
          cborValue(uint64(4)),
          rootChildRecord(
            physicalNodeKind(e.tupleChild), e.tupleChild.digest, e.tupleChild.subtree
          ),
        ),
      )
      e.digest = hashPayload(DomainValueTupleElement, elemPayload)
      records.add(
        childRecord(tupleLabel(e.tuplePos), "tuple-element", e.digest, e.subtree)
      )
    let final = buildBranches(records, schemaRoot, node.subtree, "tuple")
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("tuple")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(uint64(node.tupleElements.len))),
      (cborValue(uint64(4)), cborArray(final)),
    )
    node.digest = hashPayload(DomainValueTuple, payload)
  of vkChoice:
    computeValueDigest(node.armChild, schemaRoot)
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("choice")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(node.armIndex)),
      (cborValue(uint64(4)), cborValue(node.armSubtree)),
      (
        cborValue(uint64(5)),
        childRecord(
          choiceLabel(node.armIndex),
          physicalNodeKind(node.armChild),
          node.armChild.digest,
          node.armChild.subtree,
        ),
      ),
    )
    node.digest = hashPayload(DomainValueChoice, payload)
  of vkReference:
    computeValueDigest(node.refChild, schemaRoot)
    let payload = cborMap(
      (cborValue(uint64(0)), cborValue("reference-value")),
      (cborValue(uint64(1)), cborValue(schemaRoot)),
      (cborValue(uint64(2)), cborValue(node.subtree)),
      (cborValue(uint64(3)), cborValue(node.refRoot)),
      (cborValue(uint64(4)), cborValue(node.refSubtree)),
      (
        cborValue(uint64(5)),
        rootChildRecord(
          physicalNodeKind(node.refChild), node.refChild.digest, node.refChild.subtree
        ),
      ),
    )
    node.digest = hashPayload(DomainValueReference, payload)
  of vkListElement, vkTupleElement:
    raise newException(Exception, "element wrapper: compute the child directly")

## ---------------------------------------------------------------------------
## Value root (Section 7.4)

proc computeValueRoot*(schemaRoot, subtree: seq[byte], topNode: VNode): seq[byte] =
  ## the value-root payload commits to the single top-level value node
  let rootRecord =
    rootChildRecord(physicalNodeKind(topNode), topNode.digest, topNode.subtree)
  let payload = cborMap(
    (cborValue(uint64(0)), cborValue("value-root")),
    (cborValue(uint64(1)), cborValue(schemaRoot)),
    (cborValue(uint64(2)), cborValue(subtree)),
    (cborValue(uint64(3)), rootRecord),
  )
  hashPayload(DomainValueRoot, payload)

## ---------------------------------------------------------------------------
## Verified view (Section 7.6, Section 8)

proc verifiedView*(
    schemaRoot, subtree, valueRoot: seq[byte],
    semanticPath: CborValue,
    disclosed: CborValue,
    proofSteps: seq[(string, CborValue)],
): CborValue =
  var steps: seq[CborValue]
  for (tag, payload) in proofSteps:
    steps.add(
      cborMap((cborValue(uint64(0)), cborValue(tag)), (cborValue(uint64(1)), payload))
    )
  cborMap(
    (cborValue(uint64(0)), cborValue("verified-view")),
    (cborValue(uint64(1)), cborValue(schemaRoot)),
    (cborValue(uint64(2)), cborValue(subtree)),
    (cborValue(uint64(3)), cborValue(valueRoot)),
    (cborValue(uint64(4)), cborValue(HashProfileId)),
    (cborValue(uint64(5)), cborValue(HashSuiteId)),
    (cborValue(uint64(6)), cborValue(CommitmentModelRevision)),
    (cborValue(uint64(7)), semanticPath),
    (cborValue(uint64(8)), disclosed),
    (cborValue(uint64(9)), cborArray(steps)),
  )
