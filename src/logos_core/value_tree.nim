## Semantic value tree (LOGOS-MODULE-COMMITMENT-MODEL Section 9.3).
##
## A normalized value object binds a concrete value to the schema identity
## under which it was decoded. This module defines the in-memory value tree
## shared by the commitment model (which builds it) and the hash profile
## (which converts it to physical payloads and computes digests).
##
## Each node carries:
##   - `subtree`: the schema-subtree-root identity (a schema property, a
##     32-byte hash of the schema node under which the value is decoded).
##   - `digest`:  the physical payload digest (a value property, computed
##     bottom-up by the hash profile).
##
## NOTE: Nim forbids duplicate field names across `case` branches, so every
## variant field has a distinct name.

import cbor_profile

type
  VKind* = enum
    vkMap
    vkField
    vkAbsent
    vkList
    vkListElement
    vkTuple
    vkTupleElement
    vkChoice
    vkScalar
    vkReference

  VNode* = ref object
    subtree*: seq[byte] # schema-subtree-root identity (schema property)
    digest*: seq[byte] # physical payload digest (value property)
    case kind*: VKind
    of vkMap:
      mapFields*: seq[VNode] # vkField / vkAbsent nodes, canonical order
    of vkField:
      fieldName*: string
      fieldChild*: VNode
    of vkAbsent:
      absentName*: string
    of vkList:
      listElements*: seq[VNode] # vkListElement nodes, index order
      elemKind*: string # packable scalar kind, "" if not scalar list
      elemSubtree*: seq[byte] # element schema identity
    of vkListElement:
      elemIndex*: uint64
      elemChild*: VNode
    of vkTuple:
      tupleElements*: seq[VNode] # vkTupleElement nodes, position order
    of vkTupleElement:
      tuplePos*: uint64
      tupleChild*: VNode
    of vkChoice:
      armIndex*: uint64
      armSubtree*: seq[byte]
      armChild*: VNode
    of vkScalar:
      scalarKind*: string
      scalarData*: CborValue # bool / uint64 / int64 / tstr / bstr
    of vkReference:
      refRoot*: seq[byte]
      refSubtree*: seq[byte]
      refChild*: VNode
