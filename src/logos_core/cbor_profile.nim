## Logos deterministic CBOR profile (LOGOS-MODULE-INTERFACE §4.4, cdCDDLe §9)
##
## Self-contained CBOR codec with the Logos deterministic profile:
## - shortest-form encoding for every initial-byte argument (integers AND
##   string/array/map lengths)
## - definite lengths only (no indefinite-length items)
## - map keys sorted by bytewise lexicographic comparison of the complete
##   deterministic CBOR encoding of each map key (NOT length-first)
## - no duplicate map keys
## - major type 3 (text) values must be well-formed UTF-8
##
## The value model supports integer map keys (required by the transport
## envelope, cdCDDLe canonical model, commitment and hash payloads).
##
## Conformance check (cdCDDLe §10): re-encoding the decoded model and
## comparing the result byte-for-byte is the canonical determinism check.

import std/unicode

type
  CborKind* = enum
    ckNull
    ckUndefined
    ckBool
    ckUint
    ckNint
    ckFloat
    ckBytes
    ckText
    ckArray
    ckMap
    ckTag

  CborValue* = ref object
    case kind*: CborKind
    of ckNull, ckUndefined:
      discard
    of ckBool:
      b*: bool
    of ckUint:
      u*: uint64
    of ckNint:
      n*: int64
    of ckFloat:
      f*: float64
    of ckBytes:
      by*: seq[byte]
    of ckText:
      s*: string
    of ckArray:
      items*: seq[CborValue]
    of ckMap:
      entries*: seq[(CborValue, CborValue)] # ordered
    of ckTag:
      tag*: uint64
      val*: CborValue

type CborError* = object of Exception

proc cborError*(msg: string): ref CborError =
  newException(CborError, msg)

proc cborValue*(x: uint64): CborValue =
  CborValue(kind: ckUint, u: x)

proc cborValue*(x: int64): CborValue =
  CborValue(kind: ckNint, n: x)

proc cborValue*(x: bool): CborValue =
  CborValue(kind: ckBool, b: x)

proc cborValue*(x: string): CborValue =
  CborValue(kind: ckText, s: x)

proc cborValue*(x: seq[byte]): CborValue =
  CborValue(kind: ckBytes, by: x)

## Look up a text-keyed entry of a map; returns a null value if absent or
## if `m` is not a map.
proc mapGet*(m: CborValue, key: string): CborValue =
  if m.kind != ckMap:
    return CborValue(kind: ckNull)
  for (k, v) in m.entries:
    if k.kind == ckText and k.s == key:
      return v
  CborValue(kind: ckNull)

## Look up an integer-keyed entry of a map (schema/transport payloads use
## integer keys); returns a null value if absent or if `m` is not a map.
proc intMapGet*(m: CborValue, key: uint64): CborValue =
  if m.kind != ckMap:
    return CborValue(kind: ckNull)
  for (k, v) in m.entries:
    if k.kind == ckUint and k.u == key:
      return v
  CborValue(kind: ckNull)

proc cborArray*(xs: varargs[CborValue]): CborValue =
  result = CborValue(kind: ckArray)
  for x in xs:
    result.items.add(x)

proc cborMap*(pairs: varargs[(CborValue, CborValue)]): CborValue =
  result = CborValue(kind: ckMap)
  for p in pairs:
    result.entries.add(p)

## Bytewise lexicographic comparison of complete key encodings.
proc cmpBytes*(a, b: openArray[byte]): int =
  let n = min(a.len, b.len)
  for i in 0 ..< n:
    if a[i] != b[i]:
      return int(a[i]) - int(b[i])
  int(a.len) - int(b.len)

## Shortest-form initial byte + argument for an unsigned value.
proc writeHead(buf: var seq[byte], major: int, arg: uint64) =
  case arg
  of 0 .. 23:
    buf.add(byte((uint64(major) shl 5) or arg))
  of 24 .. 255:
    buf.add(byte((uint64(major) shl 5) or 24))
    buf.add(byte(arg))
  of 256 .. high(uint16):
    buf.add(byte((uint64(major) shl 5) or 25))
    buf.add(byte(arg shr 8))
    buf.add(byte(arg and 0xFF))
  of 65536 .. high(uint32):
    buf.add(byte((uint64(major) shl 5) or 26))
    for i in [24, 16, 8, 0]:
      buf.add(byte((arg shr i) and 0xFF))
  else:
    buf.add(byte((uint64(major) shl 5) or 27))
    for i in [56, 48, 40, 32, 24, 16, 8, 0]:
      buf.add(byte((arg shr i) and 0xFF))

proc writeValue(buf: var seq[byte], v: CborValue) =
  case v.kind
  of ckNull:
    buf.add(0xF6)
  of ckUndefined:
    buf.add(0xF7)
  of ckBool:
    if v.b:
      buf.add(0xF5)
    else:
      buf.add(0xF4)
  of ckUint:
    writeHead(buf, 0, v.u)
  of ckNint:
    writeHead(buf, 1, uint64(-v.n - 1))
  of ckFloat:
    # floats are not part of the Logos module schemas in this revision;
    # encoded here only so general CBOR (e.g. COSE) can round-trip them
    buf.add(0xFB)
    var bb: array[8, byte]
    when sizeof(float64) == 8:
      cast[ptr array[8, byte]](cast[ptr float64](addr v.f))[] = bb
    buf &= bb
  of ckBytes:
    writeHead(buf, 2, uint64(v.by.len))
    buf &= v.by
  of ckText:
    writeHead(buf, 3, uint64(v.s.len))
    for c in v.s:
      buf.add(byte(c))
  of ckArray:
    writeHead(buf, 4, uint64(v.items.len))
    for item in v.items:
      writeValue(buf, item)
  of ckMap:
    # canonical: sort entries by the complete deterministic encoding of each key
    var keyed: seq[(seq[byte], CborValue)]
    for (k, val) in v.entries:
      var kb: seq[byte]
      writeValue(kb, k)
      keyed.add((kb, val))
    # stable sort by key bytes; duplicate keys are rejected by the decoder
    let n = keyed.len
    for i in 1 ..< n:
      let key = keyed[i][0]
      var val2 = keyed[i][1]
      var j = i - 1
      while j >= 0 and cmpBytes(keyed[j][0], key) > 0:
        keyed[j + 1] = keyed[j]
        dec(j)
      keyed[j + 1] = (key, val2)
    writeHead(buf, 5, uint64(n))
    for (kb, val) in keyed:
      buf &= kb
      writeValue(buf, val)
  of ckTag:
    writeHead(buf, 6, v.tag)
    writeValue(buf, v.val)

## Canonical deterministic-CBOR encoding of a value.
proc encodeCbor*(v: CborValue): seq[byte] =
  writeValue(result, v)

proc readHead*(data: openArray[byte], pos: var int, major: var int, arg: var uint64) =
  if pos >= data.len:
    raise cborError("truncated initial byte")
  let ib = int(data[pos])
  inc(pos)
  major = ib shr 5
  let info = ib and 0x1F
  case info
  of 0 .. 23:
    arg = uint64(info)
  of 24:
    if pos >= data.len:
      raise cborError("truncated 1-byte argument")
    arg = uint64(data[pos])
    inc(pos)
  of 25:
    if pos + 1 >= data.len:
      raise cborError("truncated 2-byte argument")
    arg = uint64(data[pos]) shl 8 or uint64(data[pos + 1])
    inc(pos, 2)
  of 26:
    if pos + 3 >= data.len:
      raise cborError("truncated 4-byte argument")
    arg = 0
    for i in 0 .. 3:
      arg = arg shl 8 or uint64(data[pos + i])
    inc(pos, 4)
  of 27:
    if pos + 7 >= data.len:
      raise cborError("truncated 8-byte argument")
    arg = 0
    for i in 0 .. 7:
      arg = arg shl 8 or uint64(data[pos + i])
    inc(pos, 8)
  of 31:
    raise cborError("indefinite length not allowed")
  else:
    raise cborError("reserved initial byte")

proc readBytes(data: openArray[byte], pos: var int, n: uint64): seq[byte] =
  if n > uint64(data.len - pos):
    raise cborError("truncated bytes")
  result = data[pos ..< pos + int(n)]
  inc(pos, int(n))

proc readValue*(data: openArray[byte], pos: var int): CborValue =
  var major: int
  var arg: uint64
  readHead(data, pos, major, arg)
  case major
  of 0:
    result = cborValue(arg)
  of 1:
    if arg > uint64(high(int64)) + 1:
      raise cborError("negative integer buf of range")
    result = cborValue(int64(arg) * -1 - 1)
  of 2:
    result = CborValue(kind: ckBytes, by: readBytes(data, pos, arg))
  of 3:
    let s = readBytes(data, pos, arg)
    var str = newStringOfCap(s.len)
    for b in s:
      str.add(char(b))
    if validateUtf8(str) >= 0:
      raise cborError("text string is not valid UTF-8")
    result = CborValue(kind: ckText, s: str)
  of 4:
    result = CborValue(kind: ckArray)
    for i in 0 ..< int(arg):
      result.items.add(readValue(data, pos))
  of 5:
    result = CborValue(kind: ckMap)
    var seen: seq[seq[byte]]
    for i in 0 ..< int(arg):
      let k = readValue(data, pos)
      let val = readValue(data, pos)
      var kb: seq[byte]
      writeValue(kb, k)
      for s in seen:
        if s == kb:
          raise cborError("duplicate map key")
      seen.add(kb)
      result.entries.add((k, val))
  of 6:
    result = CborValue(kind: ckTag, tag: arg, val: readValue(data, pos))
  of 7:
    case arg
    of 25, 26:
      # float16/float32: not needed by any Logos profile; reject
      raise cborError("float16/float32 not supported")
    of 27:
      let bb = readBytes(data, pos, 8)
      var f: float64
      when sizeof(float64) == 8:
        cast[ptr float64](cast[ptr array[8, byte]](addr bb[0]))[] = f
      result = CborValue(kind: ckFloat, f: f)
    of 20:
      result = cborValue(false)
    of 21:
      result = cborValue(true)
    of 22:
      result = CborValue(kind: ckNull)
    of 23:
      result = CborValue(kind: ckUndefined)
    else:
      raise cborError("unsupported simple value")
  else:
    raise cborError("unknown major type")

proc decodeCbor*(data: openArray[byte]): CborValue =
  ## Strict decode: one complete value, no trailing bytes, no indefinite
  ## lengths, no duplicate map keys, well-formed UTF-8 text.
  var pos = 0
  result = readValue(data, pos)
  if pos != data.len:
    raise cborError("trailing bytes after complete value")

## Determinism check (cdCDDLe §10 / INTERFACE §4.4): decode strictly, re-encode
## canonically, and compare byte-for-byte.
proc validateDeterministic*(data: openArray[byte]): bool =
  var v: CborValue
  try:
    v = decodeCbor(data)
  except CborError:
    return false
  encodeCbor(v) == data

proc hexToBytes*(h: string): seq[byte] =
  for i in countUp(0, h.len - 1, 2):
    let hi =
      if h[i] <= '9':
        h[i].int - '0'.int
      else:
        h[i].int - 'a'.int + 10
    let lo =
      if h[i + 1] <= '9':
        h[i + 1].int - '0'.int
      else:
        h[i + 1].int - 'a'.int + 10
    result.add(byte(hi * 16 + lo))

proc toHex*(b: openArray[byte]): string =
  for x in b:
    result.add("0123456789abcdef"[x shr 4])
    result.add("0123456789abcdef"[x and 0xF])
