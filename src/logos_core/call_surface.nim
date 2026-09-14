## Module-side provider-call-surface descriptor builder (INTERFACE §2.6).
##
## Builds the deterministic-CBOR `provider-call-surface` value from
## contract documents, recomputing every schema root under the mandatory
## suite. Used by native module implementations in their
## `logos_<module>_call_surface()` symbol.
##
##     provider-call-surface = {
##         ? primary: provider-contract-schema,
##         interfaces: [* provider-contract-schema],
##     }
##     provider-contract-schema = {
##         commitment: logos.schema_commitment,
##         document: tstr .size (1..1048576),
##         supporting_schemas: [* provider-supporting-schema],
##     }
##     provider-supporting-schema = {
##         namespace: tstr .size (1..128),
##         commitment: logos.schema_commitment,
##         document: tstr .size (1..1048576),
##     }

import results
import commitment, hash_profile, cbor_profile

proc schemaRootOf*(
    document: string, supporting: openArray[(string, string)] = @[]
): seq[byte] =
  ## recompute the schema root for one complete CDDL document, resolving its
  ## references against the separately supplied supporting schemas (INTERFACE
  ## §2.6/§5.3, I1). Module-side builder: the document is the module's own
  ## (valid) schema; on the (unexpected) error case return an empty root so
  ## the descriptor fails runtime validation fail-closed rather than aborting
  ## the process.
  var supRefs: seq[SupportingRef]
  for (ns, doc) in supporting:
    let refR = buildSupportingRef(doc)
    if refR.isErr:
      return @[]
    supRefs.add(refR.get)
  let modelR = buildSchemaModel(document, supRefs)
  if modelR.isErr:
    return @[]
  hashPayload(DomainSchemaRoot, modelR.get)

proc commitmentMap*(schemaRoot: seq[byte]): CborValue =
  ## one `logos.schema_commitment` value (INTERFACE §5.1) — a closed map
  ## with text keys
  cborMap(
    (cborValue("commitment_model"), cborValue(CommitmentModelRevision)),
    (cborValue("hash_profile"), cborValue(HashProfileId)),
    (cborValue("hash_suite"), cborValue(HashSuiteId)),
    (cborValue("schema_root"), cborValue(schemaRoot)),
  )

proc contractEntry*(
    document: string, supporting: openArray[(string, string)]
): CborValue =
  ## one `provider-contract-schema` value (text keys); `supporting` pairs
  ## are (namespace, document) in canonical order
  var sup: seq[CborValue]
  for (ns, doc) in supporting:
    sup.add(
      cborMap(
        (cborValue("commitment"), commitmentMap(schemaRootOf(doc))),
        (cborValue("document"), cborValue(doc)),
        (cborValue("namespace"), cborValue(ns)),
      )
    )
  cborMap(
    (cborValue("commitment"), commitmentMap(schemaRootOf(document, supporting))),
    (cborValue("document"), cborValue(document)),
    (cborValue("supporting_schemas"), cborArray(sup)),
  )

proc buildCallSurface*(
    primaryDocument: string,
    primarySupporting: seq[(string, string)],
    interfaces: seq[(string, seq[(string, string)])],
): seq[byte] =
  ## the complete deterministic-CBOR descriptor. `interfaces` entries are
  ## (document, supporting) pairs in canonical order; interface entries
  ## always have empty supporting sets.
  var ifaces: seq[CborValue]
  for (doc, sup) in interfaces:
    ifaces.add(contractEntry(doc, sup))
  var desc: CborValue
  if primaryDocument.len > 0:
    desc = cborMap(
      (cborValue("interfaces"), cborArray(ifaces)),
      (cborValue("primary"), contractEntry(primaryDocument, primarySupporting)),
    )
  else:
    desc = cborMap((cborValue("interfaces"), cborArray(ifaces)))
  encodeCbor(desc)
