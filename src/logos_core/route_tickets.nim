# src/logos_core/route_tickets.nim
# The `logos.route-ticket.random-256` profile per LOGOS-MODULE-TRANSPORT
# §8.1.1.
#
# The issuer (the Runtime that owns the target provider) generates 32
# uniformly random bytes (CSPRNG) and stores the BLAKE3-256 digest with the
# complete route constraints as authority state. The raw ticket is NEVER the
# lookup key and MUST NOT appear in logs. The ticket expires no later than
# 60 s after issuance (monotonic clock) and is never reissued.
#
# The validator requires an exact 32-byte token, looks up the live record by
# digest WITHOUT consuming it, verifies every stored constraint, and then
# atomically redeems the record at session establishment (only one concurrent
# redemption succeeds). A failed Hello never consumes a live ticket.
# Consumed, expired, and revoked records are deleted. Every denial class
# produces a uniform error (no enumeration).

import std/[tables, os, strutils, sequtils], results
import ./blake3, ./cbor_profile

const
  ticketSize* = 32
  maxTicketLifetimeNanos* = 60_000_000_000.uint64 # 60 s

type
  TicketState* = enum
    tsLive
    tsConsumed
    tsRevoked

  ## Route access constraints bound to a ticket (TRANSPORT §8.1).
  ## `methodsAbsent`/`eventsAbsent` distinguish an absent list (permits every
  ## declaration of that kind, RUNTIME §9.3) from a present empty list
  ## (permits none).
  TicketAccess* = object
    methods*: seq[string] # allowed bare method names
    events*: seq[string] # allowed event names
    allowSchema*: bool # logos.schema introspection permitted
    methodsAbsent*: bool # absent methods list (permit all)
    eventsAbsent*: bool # absent events list (permit all)

  ## One stored route-ticket record (authority state). Keyed by the
  ## BLAKE3-256 digest of the raw ticket; the raw ticket is not stored.
  TicketRecord* = object
    digest*: seq[byte]
    consumer*: string # consumer runtime instance id
    provider*: string # selected provider (flat module name)
    contractRoot*: seq[byte] # selected contract schema root (32 bytes)
    routeId*: string
    endpoint*: string # exact socket path from the invocation descriptor
    access*: TicketAccess
    issuedAt*: uint64 # monotonic nanos
    expiresAt*: uint64 # monotonic nanos
    state*: TicketState

  TicketStore* = object
    records*: Table[string, TicketRecord] # hex(digest) -> record

  ## The constraints an issuer fixes before generating a ticket.
  TicketConstraints* = object
    consumer*: string
    provider*: string
    contractRoot*: seq[byte]
    routeId*: string
    endpoint*: string
    access*: TicketAccess

## A monotonic clock in nanoseconds (CLOCK_MONOTONIC on POSIX).
when defined(posix):
  type CTimespec = object
    tvSec: int64
    tvNsec: int64

  func clock_gettime(
    clockid: int32, tp: ptr CTimespec
  ): int32 {.importc: "clock_gettime".}
  const CLOCK_MONOTONIC = 1

  proc monotonicNanos*(): uint64 =
    var ts: CTimespec
    if clock_gettime(CLOCK_MONOTONIC, addr ts) != 0:
      raise newException(OSError, "clock_gettime failed")
    result = uint64(ts.tvSec) * 1_000_000_000.uint64 + uint64(ts.tvNsec)

else:
  proc monotonicNanos*(): uint64 =
    epochNanos().uint64 # fallback (non-POSIX)

## 32 uniformly random bytes from the OS CSPRNG (getrandom(2) on Linux).
when defined(posix):
  func getrandom(
    buf: pointer, len: csize_t, flags: uint32
  ): int64 {.importc: "getrandom".}

  proc randomTicket*(): seq[byte] =
    result = newSeq[byte](ticketSize)
    var filled: int64 = 0
    while filled < ticketSize.int64:
      let n = getrandom(addr result[filled.int], (ticketSize - filled.int).csize_t, 0)
      if n < 0:
        raise newException(OSError, "getrandom failed")
      filled += n

else:
  proc randomTicket*(): seq[byte] =
    result = newSeq[byte](ticketSize)
    for i in 0 ..< ticketSize:
      result[i] = rand(255).byte # non-POSIX fallback (not CSPRNG)

proc newTicketStore*(): TicketStore =
  TicketStore(records: initTable[string, TicketRecord]())

func digestHex*(d: seq[byte]): string =
  cbor_profile.toHex(d)

func blake3Seq*(data: openArray[byte]): seq[byte] =
  let a = blake3_256(data)
  result = @a

## Issue a ticket: generate 32 random bytes, store the digest + constraints.
## Returns the raw ticket (for the invocation descriptor) and the record.
proc issueTicket*(
    store: var TicketStore, c: TicketConstraints
): Result[(seq[byte], TicketRecord), string] =
  var ticket = randomTicket()
  # Collision guard: discard and regenerate if it matches an unexpired
  # ticket issued by this Runtime (TRANSPORT §8.1.1).
  let now = monotonicNanos()
  while true:
    let dg = blake3Seq(ticket)
    var collides = false
    for r in store.records.values:
      if r.state == tsLive and r.expiresAt > now and cmpBytes(r.digest, dg) == 0:
        collides = true
        break
    if not collides:
      var rec = TicketRecord(
        digest: dg,
        consumer: c.consumer,
        provider: c.provider,
        contractRoot: c.contractRoot,
        routeId: c.routeId,
        endpoint: c.endpoint,
        access: c.access,
        issuedAt: now,
        expiresAt: now + maxTicketLifetimeNanos,
        state: tsLive,
      )
      store.records[digestHex(dg)] = rec
      return ok((ticket, rec))
    ticket = randomTicket()

## Validate a presented ticket WITHOUT consuming it. Returns the live record
## if the ticket is exact-size, live, unexpired, and every constraint
## matches; otherwise a uniform error (no enumeration of the denial class).
proc validateTicket*(
    store: TicketStore,
    ticket: seq[byte],
    expectedProvider: string,
    expectedContractRoot: seq[byte],
    expectedConsumer: string,
): Result[TicketRecord, string] =
  if ticket.len != ticketSize:
    return err("not authorised")
  let dg = blake3Seq(ticket)
  let key = digestHex(dg)
  if not store.records.hasKey(key):
    return err("not authorised")
  let rec = store.records[key]
  let now = monotonicNanos()
  # Uniform denial for every constraint mismatch / expiry / revocation.
  if rec.state != tsLive:
    return err("not authorised")
  if rec.expiresAt <= now:
    return err("not authorised")
  if rec.provider != expectedProvider:
    return err("not authorised")
  if cmpBytes(rec.contractRoot, expectedContractRoot) != 0:
    return err("not authorised")
  if rec.consumer != expectedConsumer:
    return err("not authorised")
  ok(rec)

## Validate a presented ticket for a local unix-stream session WITHOUT
## consuming it. Checks exact size, live state, expiry, and the provider +
## selected-contract constraints. The consumer is taken from the record (the
## caller never supplies a replacement consumer identity, TRANSPORT §8.2).
proc validateTicketLocal*(
    store: TicketStore,
    ticket: seq[byte],
    expectedProvider: string,
    expectedContractRoot: seq[byte],
): Result[TicketRecord, string] =
  if ticket.len != ticketSize:
    return err("not authorised")
  let dg = blake3Seq(ticket)
  let key = digestHex(dg)
  if not store.records.hasKey(key):
    return err("not authorised")
  let rec = store.records[key]
  let now = monotonicNanos()
  if rec.state != tsLive:
    return err("not authorised")
  if rec.expiresAt <= now:
    return err("not authorised")
  if rec.provider != expectedProvider:
    return err("not authorised")
  if cmpBytes(rec.contractRoot, expectedContractRoot) != 0:
    return err("not authorised")
  ok(rec)

## Atomically redeem a ticket by digest: only one concurrent redemption of a
## live record succeeds. Marks it consumed (the record is retained as
## consumed so a replay is detected, then purged).
proc redeemTicket*(store: var TicketStore, digest: seq[byte]): Result[void, string] =
  let key = digestHex(digest)
  if not store.records.hasKey(key):
    return err("not authorised")
  var rec = store.records[key]
  if rec.state != tsLive:
    return err("not authorised") # already consumed or revoked (replay)
  rec.state = tsConsumed
  store.records[key] = rec
  ok()

## Revoke a ticket by digest (idempotent). A revoked record is deleted.
proc revokeTicket*(store: var TicketStore, digest: seq[byte]) =
  let key = digestHex(digest)
  if store.records.hasKey(key):
    store.records.del key

## Delete consumed and expired records (TRANSPORT §8.1.1).
proc purgeDead*(store: var TicketStore) =
  let now = monotonicNanos()
  for key in store.records.keys.toSeq:
    let rec = store.records[key]
    if rec.state == tsConsumed or rec.expiresAt <= now:
      store.records.del key

func liveCount*(store: TicketStore): int =
  for r in store.records.values:
    if r.state == tsLive:
      inc result
