# src/logos_core/transport.nim
# The `logos.transport` message envelope per LOGOS-MODULE-TRANSPORT §1.
#
# Every message is a Logos deterministic-CBOR map whose FIRST entry is
# integer key `0` = the message kind. All other top-level keys are text.
# Maps are closed: an unknown field is INVALID_PARAMS. Framing (§2.1) is a
# 4-byte big-endian length prefix followed by the CBOR message; the kind
# lives INSIDE the CBOR (there is no separate tag byte).

import results, std/net, stew/[endians2, enums]
import ./cbor_profile
from ./hash_profile import CommitmentModelRevision, HashProfileId, HashSuiteId

const
  ## Configured maximum accepted frame size (§2.1: MUST support >= 16 MiB).
  maxFrameSize* = 16 * 1024 * 1024

## Message kinds (TRANSPORT §1.1). Kind 8 (subscription-result) is allocated.
type
  TransportKind* = enum
    tkHello = 0
    tkRequest = 1
    tkResponse = 2
    tkSubscribe = 3
    tkUnsubscribe = 4
    tkEvent = 5
    tkProtocolError = 6
    tkCancel = 7
    tkSubscriptionResult = 8

  ## One `logos.schema_commitment` value (INTERFACE §5.1): a closed map with
  ## three pinned literal fields and one 32-byte schema root.
  SchemaCommitment* = object
    commitmentModel*: string
    schemaRoot*: seq[byte]
    hashProfile*: string
    hashSuite*: string

  ## One `logos.transport.payload-commitment` value: the two 32-byte roots
  ## binding a schema-typed payload value.
  PayloadCommitment* = object
    schemaSubtreeRoot*: seq[byte]
    valueRoot*: seq[byte]

  ## One `logos.transport.error-payload` value: nonzero code, optional
  ## human-readable message, optional code-specific detail.
  ErrorPayload* = object
    code*: int
    message*: Opt[string]
    detail*: Opt[CborValue]

  ## A decoded transport message (tagged by kind). Branch field names are
  ## unique because Nim forbids duplicate names across `case` branches.
  TMessage* = ref object
    case kind*: TransportKind
    of tkHello:
      module*: string
      token*: seq[byte]
      schema*: SchemaCommitment
    of tkRequest:
      callId*: uint64
      methodName*: string
      params*: CborValue
      requestCommitment*: PayloadCommitment
    of tkResponse:
      respId*: uint64
      isOk*: bool
      result*: CborValue
      resultCommitment*: PayloadCommitment
      error*: ErrorPayload
    of tkSubscribe:
      subId*: uint64
      event*: string
    of tkUnsubscribe:
      unsubId*: uint64
    of tkEvent:
      eventSub*: uint64
      eventName*: string
      data*: CborValue
      eventCommitment*: PayloadCommitment
    of tkProtocolError:
      code*: int
      message*: Opt[string]
      detail*: Opt[CborValue]
    of tkCancel:
      cancelId*: uint64
    of tkSubscriptionResult:
      resultId*: uint64
      operation*: int # tkSubscribe or tkUnsubscribe
      resultIsOk*: bool
      resultError*: ErrorPayload

# ============================================================================
# Envelope field helpers (closed-map validation)
# ============================================================================

proc fieldText(
    m: CborValue, key: string, what: string, lo, hi: int
): Result[string, string] =
  ## Required text field with a .size (lo..hi) constraint.
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == key:
      if v.kind != ckText:
        return err(what & " field '" & key & "' is not a text string")
      if v.s.len < lo or v.s.len > hi:
        return err(what & " field '" & key & "' has bad size")
      return ok(v.s)
  err(what & " is missing field '" & key & "'")

proc fieldUint(m: CborValue, key: string, what: string): Result[uint64, string] =
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == key:
      if v.kind != ckUint:
        return err(what & " field '" & key & "' is not an unsigned integer")
      return ok(v.u)
  err(what & " is missing field '" & key & "'")

proc fieldBytes(
    m: CborValue, key: string, what: string, exactLen: int = -1
): Result[seq[byte], string] =
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == key:
      if v.kind != ckBytes:
        return err(what & " field '" & key & "' is not a byte string")
      if exactLen >= 0 and v.by.len != exactLen:
        return err(what & " field '" & key & "' has bad size")
      return ok(v.by)
  err(what & " is missing field '" & key & "'")

proc fieldMap(m: CborValue, key: string, what: string): Result[CborValue, string] =
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == key:
      if v.kind != ckMap:
        return err(what & " field '" & key & "' is not a map")
      return ok(v)
  err(what & " is missing field '" & key & "'")

func hasTextKey(m: CborValue, key: string): bool =
  ## True if the map has a text key `key` (regardless of the value's kind).
  if m.kind != ckMap:
    return false
  for (k, _) in m.entries:
    if k.kind == ckText and k.s == key:
      return true
  false

proc checkClosed(
    m: CborValue, allowed: openArray[string], what: string
): Result[void, string] =
  ## Closed map: the kind key (integer 0) is allowed; every other key must be
  ## one of the allowed text keys.
  for (k, _) in m.entries:
    if k.kind == ckUint:
      if k.u != 0:
        return err(what & " has an unexpected integer field key")
      continue # the kind key
    if k.kind != ckText:
      return err(what & " has a non-text field key")
    if k.s notin allowed:
      return err(what & " has unknown field '" & k.s & "'")
  ok()

proc parseCommitment(m: CborValue): Result[SchemaCommitment, string] =
  ## `logos.schema_commitment`: closed map, pinned fields, 32-byte root.
  ?checkClosed(
    m,
    ["commitment_model", "schema_root", "hash_profile", "hash_suite"],
    "schema commitment",
  )
  let cm = ?fieldText(m, "commitment_model", "schema commitment", 1, 512)
  let hp = ?fieldText(m, "hash_profile", "schema commitment", 1, 512)
  let hs = ?fieldText(m, "hash_suite", "schema commitment", 1, 512)
  let sr = ?fieldBytes(m, "schema_root", "schema commitment", 32)
  ok(
    SchemaCommitment(
      commitmentModel: cm, schemaRoot: sr, hashProfile: hp, hashSuite: hs
    )
  )

func commitmentEqual*(a, b: SchemaCommitment): bool =
  a.commitmentModel == b.commitmentModel and a.hashProfile == b.hashProfile and
    a.hashSuite == b.hashSuite and cmpBytes(a.schemaRoot, b.schemaRoot) == 0

proc parsePayloadCommitment(m: CborValue): Result[PayloadCommitment, string] =
  ## `logos.transport.payload-commitment`: closed map, two 32-byte roots.
  ?checkClosed(m, ["schema_subtree_root", "value_root"], "payload commitment")
  let ssr = ?fieldBytes(m, "schema_subtree_root", "payload commitment", 32)
  let vr = ?fieldBytes(m, "value_root", "payload commitment", 32)
  ok(PayloadCommitment(schemaSubtreeRoot: ssr, valueRoot: vr))

proc parseErrorPayload(m: CborValue): Result[ErrorPayload, string] =
  ## `logos.transport.error-payload`: nonzero code, optional message/detail.
  ?checkClosed(m, ["code", "message", "detail"], "error payload")
  let code = ?fieldUint(m, "code", "error payload")
  if code == 0:
    return err("error payload code must be nonzero")
  var msg = Opt.none(string)
  var det = Opt.none(CborValue)
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == "message":
      if v.kind != ckText or v.s.len > 512:
        return err("error payload message has bad size")
      msg = Opt.some(v.s)
    elif k.kind == ckText and k.s == "detail":
      det = Opt.some(v)
  ok(ErrorPayload(code: int(code), message: msg, detail: det))

# ============================================================================
# Decode + validate one envelope message
# ============================================================================

proc decodeMessage*(raw: seq[byte]): Result[TMessage, string] =
  ## Decode and validate one framed CBOR message body (without the length
  ## prefix). Enforces: deterministic CBOR, first entry is integer key 0,
  ## known kind, closed map, required fields, field types/sizes.
  var v: CborValue
  try:
    v = decodeCbor(raw)
  except CborError as e:
    return err("envelope is not valid CBOR: " & e.msg)
  if not validateDeterministic(raw):
    return err("envelope is not deterministic CBOR")
  if v.kind != ckMap:
    return err("envelope is not a map")
  # The first map entry MUST be integer key 0 (the kind).
  var first = true
  var kindVal: CborValue
  for (k, val) in v.entries:
    if first:
      first = false
      if k.kind != ckUint or k.u != 0:
        return err("first map entry is not integer key 0")
      kindVal = val
    else:
      break
  if kindVal.kind != ckUint:
    return err("message kind is not an unsigned integer")
  if kindVal.u > 8:
    return err("unknown or unallocated message kind " & $kindVal.u)
  let msg = TMessage(kind: TransportKind(kindVal.u.int))
  case msg.kind
  of tkHello:
    ?checkClosed(v, ["module", "token", "schema"], "hello")
    msg.module = ?fieldText(v, "module", "hello", 1, 64)
    msg.token = ?fieldBytes(v, "token", "hello")
    msg.schema = ?parseCommitment(?fieldMap(v, "schema", "hello"))
  of tkRequest:
    ?checkClosed(v, ["id", "method", "params", "commitment"], "request")
    msg.callId = ?fieldUint(v, "id", "request")
    msg.methodName = ?fieldText(v, "method", "request", 1, 128)
    msg.params = ?fieldMap(v, "params", "request")
    msg.requestCommitment =
      ?parsePayloadCommitment(?fieldMap(v, "commitment", "request"))
  of tkResponse:
    # Exactly one of {result, commitment} or {error}.
    let hasResult = hasTextKey(v, "result")
    let hasError = hasTextKey(v, "error")
    if hasResult == hasError:
      return err("response must have exactly one of result or error")
    ?checkClosed(v, ["id", "result", "commitment", "error"], "response")
    msg.respId = ?fieldUint(v, "id", "response")
    if hasResult:
      msg.isOk = true
      msg.result = ?fieldMap(v, "result", "response")
      msg.resultCommitment =
        ?parsePayloadCommitment(?fieldMap(v, "commitment", "response"))
    else:
      msg.isOk = false
      msg.error = ?parseErrorPayload(?fieldMap(v, "error", "response"))
  of tkSubscribe:
    ?checkClosed(v, ["id", "event"], "subscribe")
    msg.subId = ?fieldUint(v, "id", "subscribe")
    msg.event = ?fieldText(v, "event", "subscribe", 1, 128)
  of tkUnsubscribe:
    ?checkClosed(v, ["id"], "unsubscribe")
    msg.unsubId = ?fieldUint(v, "id", "unsubscribe")
  of tkEvent:
    ?checkClosed(v, ["sub", "event", "data", "commitment"], "event")
    msg.eventSub = ?fieldUint(v, "sub", "event")
    msg.eventName = ?fieldText(v, "event", "event", 1, 128)
    msg.data = ?fieldMap(v, "data", "event")
    msg.eventCommitment = ?parsePayloadCommitment(?fieldMap(v, "commitment", "event"))
  of tkProtocolError:
    ?checkClosed(v, ["code", "message", "detail"], "protocol-error")
    let pcode = ?fieldUint(v, "code", "protocol-error")
    msg.code = int(pcode)
    if msg.code == 0:
      return err("protocol-error code must be nonzero")
    for (k, val) in v.entries:
      if k.kind == ckText and k.s == "message":
        if val.kind != ckText or val.s.len > 512:
          return err("protocol-error message has bad size")
        msg.message = Opt.some(val.s)
      elif k.kind == ckText and k.s == "detail":
        msg.detail = Opt.some(val)
  of tkCancel:
    ?checkClosed(v, ["id"], "cancel")
    msg.cancelId = ?fieldUint(v, "id", "cancel")
  of tkSubscriptionResult:
    ?checkClosed(v, ["id", "operation", "error"], "subscription-result")
    msg.resultId = ?fieldUint(v, "id", "subscription-result")
    let op = ?fieldUint(v, "operation", "subscription-result")
    if op != 3 and op != 4:
      return err("subscription-result operation must be subscribe or unsubscribe")
    msg.operation = int(op)
    msg.resultIsOk = true
    for (k, val) in v.entries:
      if k.kind == ckText and k.s == "error":
        msg.resultIsOk = false
        msg.resultError = ?parseErrorPayload(val)
  ok(msg)

# ============================================================================
# Encode one envelope message
# ============================================================================

func commitmentCbor(c: SchemaCommitment): CborValue =
  cborMap(
    (cborValue("commitment_model"), cborValue(c.commitmentModel)),
    (cborValue("hash_profile"), cborValue(c.hashProfile)),
    (cborValue("hash_suite"), cborValue(c.hashSuite)),
    (cborValue("schema_root"), cborValue(c.schemaRoot)),
  )

func payloadCommitmentCbor(c: PayloadCommitment): CborValue =
  cborMap(
    (cborValue("schema_subtree_root"), cborValue(c.schemaSubtreeRoot)),
    (cborValue("value_root"), cborValue(c.valueRoot)),
  )

func errorPayloadCbor(e: ErrorPayload): CborValue =
  var pairs: seq[(CborValue, CborValue)] =
    @[(cborValue("code"), cborValue(uint64(e.code)))]
  if e.message.isSome:
    pairs.add((cborValue("message"), cborValue(e.message.get)))
  if e.detail.isSome:
    pairs.add((cborValue("detail"), e.detail.get))
  cborMap(pairs)

proc encodeMessage*(msg: TMessage): seq[byte] =
  ## Encode one message as a deterministic-CBOR map (kind first at key 0).
  var m: CborValue
  case msg.kind
  of tkHello:
    m = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(0))),
      (cborValue("module"), cborValue(msg.module)),
      (cborValue("schema"), commitmentCbor(msg.schema)),
      (cborValue("token"), cborValue(msg.token)),
    )
  of tkRequest:
    m = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(1))),
      (cborValue("commitment"), payloadCommitmentCbor(msg.requestCommitment)),
      (cborValue("id"), cborValue(msg.callId)),
      (cborValue("method"), cborValue(msg.methodName)),
      (cborValue("params"), msg.params),
    )
  of tkResponse:
    if msg.isOk:
      m = cborMap(
        (cborValue(uint64(0)), cborValue(uint64(2))),
        (cborValue("commitment"), payloadCommitmentCbor(msg.resultCommitment)),
        (cborValue("id"), cborValue(msg.respId)),
        (cborValue("result"), msg.result),
      )
    else:
      m = cborMap(
        (cborValue(uint64(0)), cborValue(uint64(2))),
        (cborValue("error"), errorPayloadCbor(msg.error)),
        (cborValue("id"), cborValue(msg.respId)),
      )
  of tkSubscribe:
    m = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(3))),
      (cborValue("event"), cborValue(msg.event)),
      (cborValue("id"), cborValue(msg.subId)),
    )
  of tkUnsubscribe:
    m = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(4))),
      (cborValue("id"), cborValue(msg.unsubId)),
    )
  of tkEvent:
    m = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(5))),
      (cborValue("commitment"), payloadCommitmentCbor(msg.eventCommitment)),
      (cborValue("data"), msg.data),
      (cborValue("event"), cborValue(msg.eventName)),
      (cborValue("sub"), cborValue(msg.eventSub)),
    )
  of tkProtocolError:
    var pairs: seq[(CborValue, CborValue)] = @[
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue("code"), cborValue(uint64(msg.code))),
    ]
    if msg.message.isSome:
      pairs.add((cborValue("message"), cborValue(msg.message.get)))
    if msg.detail.isSome:
      pairs.add((cborValue("detail"), msg.detail.get))
    m = cborMap(pairs)
  of tkCancel:
    m = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(7))),
      (cborValue("id"), cborValue(msg.cancelId)),
    )
  of tkSubscriptionResult:
    var pairs: seq[(CborValue, CborValue)] = @[
      (cborValue(uint64(0)), cborValue(uint64(8))),
      (cborValue("id"), cborValue(msg.resultId)),
      (cborValue("operation"), cborValue(uint64(msg.operation))),
    ]
    if not msg.resultIsOk:
      pairs.add((cborValue("error"), errorPayloadCbor(msg.resultError)))
    m = cborMap(pairs)
  encodeCbor(m)

# ============================================================================
# ProtocolError / error-response constructors
# ============================================================================

func protocolError*(code: int, message: string = ""): TMessage =
  let m = TMessage(kind: tkProtocolError)
  m.code = code
  if message.len > 0:
    m.message = Opt.some(message)
  m

func responseError*(respId: uint64, code: int, message: string = ""): TMessage =
  let m = TMessage(kind: tkResponse)
  m.respId = respId
  m.isOk = false
  m.error = ErrorPayload(
    code: code,
    message:
      if message.len > 0:
        Opt.some(message)
      else:
        Opt.none(string),
  )
  m

# ============================================================================
# Stream framing (§2.1): 4-byte big-endian length prefix + CBOR message
# ============================================================================

proc frameMessage*(msg: TMessage): seq[byte] =
  let body = encodeMessage(msg)
  if body.len > maxFrameSize:
    raise newException(ValueError, "message exceeds the configured frame size")
  var framed = newSeq[byte](4)
  framed[0] = (body.len shr 24).byte
  framed[1] = (body.len shr 16).byte
  framed[2] = (body.len shr 8).byte
  framed[3] = body.len.byte
  framed.add(body)
  framed

proc readExact(
    client: Socket, dest: var openArray[byte], size: int
): Result[void, string] =
  var read = 0
  while read < size:
    let chunk = client.recv(addr dest[read], size - read)
    if chunk <= 0:
      return err("connection closed during read")
    read += chunk
  ok()

proc sendFramed*(client: Socket, msg: TMessage): Result[void, string] =
  let bytes = frameMessage(msg)
  var written = 0
  while written < bytes.len:
    let chunk = client.send(addr bytes[written], bytes.len - written)
    if chunk <= 0:
      return err("failed to send transport message")
    written += chunk
  ok()

proc recvFramed*(client: Socket): Result[TMessage, string] =
  ## Read one framed message. Enforces the configured maximum frame size
  ## BEFORE allocating the body (§2.1).
  var header: array[4, byte]
  ?readExact(client, header, 4)
  let length =
    (int(header[0]) shl 24) or (int(header[1]) shl 16) or (int(header[2]) shl 8) or
    int(header[3])
  if length > maxFrameSize:
    return err("frame length " & $length & " exceeds the configured maximum")
  var body = newSeq[byte](length)
  if length > 0:
    ?readExact(client, body, length)
  decodeMessage(body)

# ============================================================================
# Legacy framing (pre-envelope) — used by the plain-TCP development path
# (tcp_host.nim / tcp_modules.nim). The conformant local transport is the
# TMessage envelope above (unix-stream); this tag+payload framing is kept
# only so the legacy TCP path still builds. NOT a spec transport.
# ============================================================================

type
  TransportTag* = enum
    tHello = 0
    tRequest = 1
    tResponse = 2
    tSubscribe = 3
    tUnsubscribe = 4
    tEvent = 5
    tProtocolError = 6
    tCancel = 7

  ## A length-prefixed tag+payload message (legacy framing).
  TransportMessage* = object
    tag*: TransportTag
    payload*: seq[byte]

proc encodeMessage*(msg: TransportMessage): seq[byte] =
  ## Legacy: 4-byte big-endian length + 1-byte tag + payload.
  result.add msg.payload.len.uint32.toBytesBE()
  result.add(byte(msg.tag.ord))
  result.add(msg.payload)

proc sendTransportMessage*(
    client: Socket, msg: TransportMessage
): Result[void, string] =
  let bytes = encodeMessage(msg)
  var written = 0
  while written < bytes.len:
    let chunk = client.send(addr bytes[written], bytes.len - written)
    if chunk <= 0:
      return err("failed to send transport message")
    written += chunk
  ok()

proc receiveTransportMessage*(client: Socket): Result[TransportMessage, string] =
  var header: array[4, byte]
  ?readExact(client, header, 4)
  let length = uint32.fromBytesBE(header).int
  # bound the legacy frame allocation (T5: previously up to ~4 GiB)
  if length < 1 or length > maxFrameSize:
    return err("invalid transport frame length")
  var rawTag: array[1, byte]
  ?readExact(client, rawTag, 1)
  var tag: TransportTag
  if not tag.checkedEnumAssign(rawTag[0].int):
    return err("unknown transport tag")
  var payload = newSeqUninit[byte](length)
  ?readExact(client, payload, length)
  ok TransportMessage(tag: tag, payload: payload)
