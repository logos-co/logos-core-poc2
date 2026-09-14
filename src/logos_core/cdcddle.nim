## cdCDDLe (LOGOS-CORE-CDCDDLE) — parse, canonicalize, encode, check
##
## Implements the supported CDDL construct subset (spec §5.1), the
## name-preserving canonical model (§6-§8), deterministic CBOR encoding
## (§9), and decoding/checking (§10).
##
## Pipeline: source text -> parse -> resolve -> canonicalize -> encode.
## Conformance: the `storage-like` normative vector (Appendix A) must
## canonicalize to exactly 522 deterministic-CBOR bytes.

import std/[strutils, sets]
import results
import cbor_profile

type CddlError* = object of Exception

proc cddlError*(msg: string): ref CddlError =
  newException(CddlError, msg)

## ---------------------------------------------------------------------------
## Lexer

type
  TokKind* = enum
    tkIdent
    tkText
    tkBytes
    tkUint
    tkNint
    tkBool
    tkEq
    tkLBrace
    tkRBrace
    tkLBrack
    tkRBrack
    tkLParen
    tkRParen
    tkSlash
    tkQMark
    tkStar
    tkColon
    tkComma
    tkDotDot
    tkDotSize
    tkDotOther
    tkEnd

  Tok* = object
    kind*: TokKind
    text*: string
    by*: seq[byte]
    uval*: uint64
    nval*: int64

  Lexer = object
    src: string
    pos: int
    toks: seq[Tok]

proc isEAlpha(c: char): bool =
  c in {'A' .. 'Z', 'a' .. 'z'} or c in {'_', '@', '$'}

proc isDigit(c: char): bool =
  c in {'0' .. '9'}

proc lexError(lx: Lexer, msg: string): ref CddlError =
  cddlError("lex error at offset " & $lx.pos & ": " & msg)

proc skipWsAndComments(lx: var Lexer) =
  while lx.pos < lx.src.len:
    let c = lx.src[lx.pos]
    if c in {' ', '\t', '\r', '\n'}:
      inc(lx.pos)
    elif c == ';':
      while lx.pos < lx.src.len and lx.src[lx.pos] notin {'\n', '\r'}:
        inc(lx.pos)
    else:
      break

proc addTok(lx: var Lexer, t: Tok) =
  lx.toks.add(t)

proc isPrintable(c: char): bool =
  c >= ' ' and c <= '~'

proc lexText(lx: var Lexer) =
  # text = %x22 *SCHAR %x22 ; SESC = \" (%x20-7E / %x80-10FFFD)
  inc(lx.pos) # opening quote
  var s = ""
  while true:
    if lx.pos >= lx.src.len:
      raise lexError(lx, "unterminated text string")
    let c = lx.src[lx.pos]
    if c == '"':
      inc(lx.pos)
      break
    elif c == '\\':
      if lx.pos + 1 >= lx.src.len:
        raise lexError(lx, "dangling escape in text string")
      let e = lx.src[lx.pos + 1]
      if not isPrintable(e):
        raise lexError(lx, "invalid escape character")
      s.add(e)
      inc(lx.pos, 2)
    else:
      if not isPrintable(c):
        raise lexError(lx, "invalid character in text string")
      s.add(c)
      inc(lx.pos)
  addTok(lx, Tok(kind: tkText, text: s))

proc lexBytesWithQual(lx: var Lexer, qual: string) =
  inc(lx.pos) # opening quote
  var content = ""
  while true:
    if lx.pos >= lx.src.len:
      raise lexError(lx, "unterminated byte string")
    let c = lx.src[lx.pos]
    if c == '\'':
      inc(lx.pos)
      break
    elif c == '\\':
      if lx.pos + 1 >= lx.src.len:
        raise lexError(lx, "dangling escape in byte string")
      content.add(lx.src[lx.pos + 1])
      inc(lx.pos, 2)
    else:
      content.add(c)
      inc(lx.pos)
  case qual
  of "h":
    var c2 = content
    # strip whitespace
    var hexd = ""
    for ch in c2:
      if ch notin {' ', '\t', '\r', '\n'}:
        hexd.add(ch)
    if hexd.len mod 2 != 0:
      raise lexError(lx, "odd-length hex byte string")
    var b: seq[byte]
    for i in countUp(0, hexd.len - 1, 2):
      let hi = "0123456789abcdef".find(hexd[i].toLowerAscii)
      let lo = "0123456789abcdef".find(hexd[i + 1].toLowerAscii)
      if hi < 0 or lo < 0:
        raise lexError(lx, "invalid hex digit in byte string")
      b.add(byte(hi * 16 + lo))
    addTok(lx, Tok(kind: tkBytes, by: b))
  else:
    raise lexError(lx, "unsupported byte string qualifier: " & qual)

proc lexNumber(lx: var Lexer) =
  var s = ""
  var neg = false
  if lx.src[lx.pos] == '-':
    neg = true
    s.add('-')
    inc(lx.pos)
  # first digit(s)
  while lx.pos < lx.src.len and lx.src[lx.pos].isDigit:
    s.add(lx.src[lx.pos])
    inc(lx.pos)
  if s.len == (if neg: 1 else: 0):
    raise lexError(lx, "incomplete number")
  # radix prefix 0x / 0b
  if s.len >= 2 and s[s.len - 2] == '0' and s[s.len - 1] in {'x', 'b'}:
    let radix = if s[s.len - 1] == 'x': 16 else: 2
    while lx.pos < lx.src.len and (
      lx.src[lx.pos].isDigit or
      (radix == 16 and lx.src[lx.pos] in {'A' .. 'Z', 'a' .. 'z'})
    )
    :
      s.add(lx.src[lx.pos])
      inc(lx.pos)
    if s.len <= (if neg: 2 else: 2):
      raise lexError(lx, "empty radix literal: " & s)
  var val: uint64
  let body =
    if neg:
      s[1 ..^ 1]
    else:
      s
  if body.len >= 2 and body[0] == '0' and body[1] in {'x', 'b'}:
    for ch in body[2 ..^ 1]:
      let d = "0123456789abcdef".find(ch.toLowerAscii)
      if d < 0:
        raise lexError(lx, "invalid digit in radix literal: " & s)
      val = val * 16.uint64 + uint64(d)
  else:
    if body.len > 1 and body[0] == '0':
      raise lexError(lx, "leading zeros not allowed in decimal: " & s)
    for ch in body:
      val = val * 10.uint64 + uint64(ch.int - '0'.int)
  if val > uint64(high(int64)) + 1:
    raise lexError(lx, "number out of range: " & s)
  if neg:
    addTok(lx, Tok(kind: tkNint, text: s, nval: -int64(val)))
  else:
    addTok(lx, Tok(kind: tkUint, text: s, uval: val))

proc lexIdent(lx: var Lexer) =
  # id = EALPHA *(*("-" / ".") (EALPHA / DIGIT))
  var s = ""
  s.add(lx.src[lx.pos])
  inc(lx.pos)
  while lx.pos < lx.src.len:
    let c = lx.src[lx.pos]
    if c in {'-', '.'}:
      if lx.pos + 1 < lx.src.len and
          (isEAlpha(lx.src[lx.pos + 1]) or lx.src[lx.pos + 1].isDigit):
        s.add(c)
        s.add(lx.src[lx.pos + 1])
        inc(lx.pos, 2)
      else:
        break
    elif isEAlpha(c) or c.isDigit:
      s.add(c)
      inc(lx.pos)
    else:
      break
  addTok(lx, Tok(kind: tkIdent, text: s))

proc lex*(src: string): seq[Tok] =
  var lx = Lexer(src: src)
  while true:
    lx.skipWsAndComments()
    if lx.pos >= lx.src.len:
      break
    let c = lx.src[lx.pos]
    case c
    of '"':
      lexText(lx)
    of '0' .. '9':
      lexNumber(lx)
    of '-':
      if lx.pos + 1 < lx.src.len and lx.src[lx.pos + 1].isDigit:
        lexNumber(lx)
      else:
        raise lexError(lx, "unexpected '-'")
    of 'a' .. 'z', 'A' .. 'Z', '_', '@', '$':
      # may be an identifier, a keyword, or a byte-string qualifier (h'...')
      let start = lx.pos
      lexIdent(lx)
      let name = lx.toks[^1].text
      if lx.pos < lx.src.len and lx.src[lx.pos] == '\'':
        # byte string: drop the identifier token, lex the quoted bytes
        lx.toks.setLen(lx.toks.len - 1)
        lx.pos = start
        # re-scan the qualifier identifier to know its length
        var qual = ""
        while lx.pos < lx.src.len and lx.src[lx.pos] != '\'':
          qual.add(lx.src[lx.pos])
          inc(lx.pos)
        lexBytesWithQual(lx, qual)
      elif name == "true" or name == "false":
        lx.toks.setLen(lx.toks.len - 1)
        addTok(lx, Tok(kind: tkBool, text: name))
    of '=':
      addTok(lx, Tok(kind: tkEq))
      inc(lx.pos)
    of '{':
      addTok(lx, Tok(kind: tkLBrace))
      inc(lx.pos)
    of '}':
      addTok(lx, Tok(kind: tkRBrace))
      inc(lx.pos)
    of '[':
      addTok(lx, Tok(kind: tkLBrack))
      inc(lx.pos)
    of ']':
      addTok(lx, Tok(kind: tkRBrack))
      inc(lx.pos)
    of '(':
      addTok(lx, Tok(kind: tkLParen))
      inc(lx.pos)
    of ')':
      addTok(lx, Tok(kind: tkRParen))
      inc(lx.pos)
    of '/':
      addTok(lx, Tok(kind: tkSlash))
      inc(lx.pos)
    of '?':
      addTok(lx, Tok(kind: tkQMark))
      inc(lx.pos)
    of '*':
      addTok(lx, Tok(kind: tkStar))
      inc(lx.pos)
    of ':':
      addTok(lx, Tok(kind: tkColon))
      inc(lx.pos)
    of ',':
      addTok(lx, Tok(kind: tkComma))
      inc(lx.pos)
    of '.':
      if lx.pos + 1 < lx.src.len and lx.src[lx.pos + 1] == '.':
        addTok(lx, Tok(kind: tkDotDot))
        inc(lx.pos, 2)
      elif lx.pos + 5 <= lx.src.len and lx.src[lx.pos .. lx.pos + 4] == ".size":
        addTok(lx, Tok(kind: tkDotSize))
        inc(lx.pos, 5)
      else:
        addTok(lx, Tok(kind: tkDotOther))
        inc(lx.pos)
    else:
      raise lexError(lx, "unexpected character: " & $c)
  addTok(lx, Tok(kind: tkEnd))
  result = lx.toks

## ---------------------------------------------------------------------------
## AST

type
  CddlOccurrence* = enum
    occRequired
    occOptional
    occUnbounded

  CddlNodeKind* = enum
    nkUint
    nkNint
    nkBool
    nkTstr
    nkBstr
    nkPrimitive
    nkRef
    nkArray
    nkMap
    nkChoice
    nkRange
    nkSize

  CddlNode* = ref object
    case kind*: CddlNodeKind
    of nkUint:
      u*: uint64
    of nkNint:
      n*: int64
    of nkBool:
      b*: bool
    of nkTstr:
      s*: string
    of nkBstr:
      by*: seq[byte]
    of nkPrimitive, nkRef:
      name*: string
    of nkArray, nkMap:
      members*: seq[CddlMember]
    of nkChoice:
      alts*: seq[CddlNode]
    of nkRange:
      lo*, hi*: CddlNode
    of nkSize:
      target*, controller*: CddlNode

  CddlMember* = object
    key*: string
    hasKey*: bool
    ty*: CddlNode
    occ*: CddlOccurrence

  CddlRule* = object
    name*: string
    body*: CddlNode

proc isPrimitiveName(n: string): bool =
  n == "uint" or n == "bool" or n == "tstr" or n == "bstr"

proc validCddlName*(s: string): bool =
  ## RFC 8610 identifier: id = EALPHA *(*("-" / ".") (EALPHA / DIGIT))
  if s.len == 0 or not isEAlpha(s[0]):
    return false
  var i = 1
  while i < s.len:
    let c = s[i]
    if c in {'-', '.'}:
      if i + 1 >= s.len or not (isEAlpha(s[i + 1]) or s[i + 1].isDigit):
        return false
      inc(i, 2)
    elif isEAlpha(c) or c.isDigit:
      inc(i)
    else:
      return false
  true

## ---------------------------------------------------------------------------
## Parser

type Parser = object
  toks: seq[Tok]
  pos: int

proc perr(p: Parser, msg: string): ref CddlError =
  cddlError(
    "parse error near token " & $p.pos & " (" &
      (if p.pos < p.toks.len: p.toks[p.pos].text else: "end") & "): " & msg
  )

proc peek(p: Parser): Tok =
  p.toks[p.pos] # tkEnd sentinel is always present at the tail

proc advance(p: var Parser): Tok =
  result = p.peek()
  if p.pos < p.toks.len - 1:
    inc(p.pos)

proc expect(p: var Parser, k: TokKind, what: string): Tok =
  if p.peek().kind != k:
    raise perr(p, "expected " & what)
  advance(p)

proc parseType(p: var Parser): CddlNode
proc parseType1(p: var Parser): CddlNode

proc parseType2(p: var Parser): CddlNode =
  let t = p.peek()
  case t.kind
  of tkUint:
    discard advance(p)
    result = CddlNode(kind: nkUint, u: t.uval)
  of tkNint:
    discard advance(p)
    result = CddlNode(kind: nkNint, n: t.nval)
  of tkBool:
    discard advance(p)
    result = CddlNode(kind: nkBool, b: t.text == "true")
  of tkText:
    discard advance(p)
    result = CddlNode(kind: nkTstr, s: t.text)
  of tkBytes:
    discard advance(p)
    result = CddlNode(kind: nkBstr, by: t.by)
  of tkIdent:
    discard advance(p)
    if isPrimitiveName(t.text):
      result = CddlNode(kind: nkPrimitive, name: t.text)
    else:
      result = CddlNode(kind: nkRef, name: t.text)
  of tkLParen:
    discard advance(p)
    let inner = parseType(p)
    discard expect(p, tkRParen, "')'")
    result = inner # parentheses are removed
  of tkLBrack:
    discard advance(p)
    var members: seq[CddlMember]
    if p.peek().kind == tkStar:
      discard advance(p)
      let ty = parseType(p)
      members.add(CddlMember(ty: ty, occ: occUnbounded))
    else:
      while p.peek().kind != tkRBrack:
        if p.peek().kind == tkQMark:
          raise perr(p, "? occurrence not allowed on array member")
        let ty = parseType(p)
        members.add(CddlMember(ty: ty, occ: occRequired))
        if p.peek().kind == tkComma:
          discard advance(p)
        else:
          break
    discard expect(p, tkRBrack, "']'")
    result = CddlNode(kind: nkArray, members: members)
  of tkLBrace:
    discard advance(p)
    var members: seq[CddlMember]
    while p.peek().kind != tkRBrace:
      var m: CddlMember
      if p.peek().kind == tkQMark:
        discard advance(p)
        m.occ = occOptional
      elif p.peek().kind == tkStar:
        raise perr(p, "* occurrence not allowed on map member")
      else:
        m.occ = occRequired
      if p.peek().kind == tkIdent and p.pos + 1 < p.toks.len and
          p.toks[p.pos + 1].kind == tkColon:
        m.key = advance(p).text
        discard advance(p) # ':'
        m.hasKey = true
      elif p.peek().kind == tkText and p.pos + 1 < p.toks.len and
          p.toks[p.pos + 1].kind == tkColon:
        raise perr(p, "non-bareword map keys are unsupported")
      m.ty = parseType(p)
      members.add(m)
      if p.peek().kind == tkComma:
        discard advance(p)
      else:
        break
    discard expect(p, tkRBrace, "'}'")
    result = CddlNode(kind: nkMap, members: members)
  else:
    raise perr(p, "expected a type, found " & $t.kind)

proc parseType1(p: var Parser): CddlNode =
  var node = parseType2(p)
  case p.peek().kind
  of tkDotDot:
    discard advance(p)
    let hi = parseType2(p)
    if node.kind notin {nkUint, nkNint} or hi.kind notin {nkUint, nkNint}:
      raise perr(p, "range bounds must be integer literals")
    result = CddlNode(kind: nkRange, lo: node, hi: hi)
  of tkDotSize:
    discard advance(p)
    let controller = parseType2(p)
    if node.kind != nkPrimitive or
        (node.name != "uint" and node.name != "tstr" and node.name != "bstr"):
      raise perr(p, ".size target must be uint, tstr, or bstr")
    result = CddlNode(kind: nkSize, target: node, controller: controller)
  of tkDotOther:
    raise perr(p, "unsupported control operator")
  else:
    result = node

proc parseType(p: var Parser): CddlNode =
  # type = type1 *( "/" type1 )
  var alts: seq[CddlNode]
  alts.add(parseType1(p))
  while p.peek().kind == tkSlash:
    discard advance(p)
    alts.add(parseType1(p))
  if alts.len == 1:
    result = alts[0]
  else:
    result = CddlNode(kind: nkChoice, alts: alts)

proc parseCddlImpl*(src: string): seq[CddlRule] =
  var p = Parser(toks: lex(src))
  while p.peek().kind != tkEnd:
    let name = advance(p)
    if name.kind != tkIdent:
      raise perr(p, "expected rule name")
    if not validCddlName(name.text):
      raise perr(p, "invalid rule name: " & name.text)
    discard expect(p, tkEq, "'='")
    let body = parseType(p)
    result.add(CddlRule(name: name.text, body: body))
  if result.len == 0:
    raise cddlError("empty CDDL document")

## Parse source CDDL text into the rule AST. Errors are returned as a
## Result (never raised) so a malformed module-supplied document cannot
## abort the runtime process (K10).
proc parseCddl*(src: string): Result[seq[CddlRule], string] =
  try:
    ok(parseCddlImpl(src))
  except CddlError as e:
    err(e.msg)

## ---------------------------------------------------------------------------
## Canonicalization (spec §7-§8)

proc canonNode(n: CddlNode): CborValue
proc canonMember(m: CddlMember, isMap: bool): CborValue

proc canonIntLiteral(n: CddlNode): CborValue =
  case n.kind
  of nkUint:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("uint")),
      (cborValue(uint64(2)), cborValue(n.u)),
    )
  of nkNint:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("nint")),
      (cborValue(uint64(2)), cborValue(n.n)),
    )
  else:
    raise cddlError("range bound is not an integer literal")

proc canonNode(n: CddlNode): CborValue =
  case n.kind
  of nkUint:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("uint")),
      (cborValue(uint64(2)), cborValue(n.u)),
    )
  of nkNint:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("nint")),
      (cborValue(uint64(2)), cborValue(n.n)),
    )
  of nkBool:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("bool")),
      (cborValue(uint64(2)), cborValue(n.b)),
    )
  of nkTstr:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("tstr")),
      (cborValue(uint64(2)), cborValue(n.s)),
    )
  of nkBstr:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(6))),
      (cborValue(uint64(1)), cborValue("bstr")),
      (cborValue(uint64(2)), cborValue(n.by)),
    )
  of nkPrimitive:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(5))),
      (cborValue(uint64(1)), cborValue(n.name)),
    )
  of nkRef:
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(3))),
      (cborValue(uint64(1)), cborValue(n.name)),
    )
  of nkArray:
    var mems: seq[CborValue]
    for m in n.members:
      mems.add(canonMember(m, isMap = false))
    let group = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(9))),
      (cborValue(uint64(1)), cborArray(mems)),
    )
    cborMap((cborValue(uint64(0)), cborValue(uint64(7))), (cborValue(uint64(1)), group))
  of nkMap:
    # map members sorted by text key (§7.1)
    var mems = n.members
    let nm = mems.len
    for i in 1 ..< nm:
      let key = mems[i]
      var j = i - 1
      while j >= 0 and mems[j].key > key.key:
        mems[j + 1] = mems[j]
        dec(j)
      mems[j + 1] = key
    var cmems: seq[CborValue]
    for m in mems:
      cmems.add(canonMember(m, isMap = true))
    let group = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(9))),
      (cborValue(uint64(1)), cborArray(cmems)),
    )
    cborMap((cborValue(uint64(0)), cborValue(uint64(8))), (cborValue(uint64(1)), group))
  of nkChoice:
    # flatten nested choices, preserving resolved alternative order (§7.2)
    var flat: seq[CborValue]
    for a in n.alts:
      let ca = canonNode(a)
      if ca.kind == ckMap and ca.entries.len >= 1 and ca.entries[0][0].kind == ckUint and
          ca.entries[0][0].u == 12:
        for alt in ca.entries[1][1].items:
          flat.add(alt)
      else:
        flat.add(ca)
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(12))),
      (cborValue(uint64(1)), cborArray(flat)),
    )
  of nkRange:
    if n.lo.kind == nkUint and n.hi.kind == nkUint and n.lo.u == n.hi.u:
      return canonNode(n.lo) # equal bounds -> single literal
    if n.lo.kind == nkUint and n.hi.kind == nkUint and n.lo.u > n.hi.u:
      raise cddlError("range lower bound exceeds upper bound")
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(13))),
      (cborValue(uint64(1)), canonIntLiteral(n.lo)),
      (cborValue(uint64(2)), canonIntLiteral(n.hi)),
      (cborValue(uint64(3)), cborValue(true)),
      (cborValue(uint64(4)), cborValue(true)),
    )
  of nkSize:
    # controller: uint literal, or range (equal bounds -> single literal)
    var ctrl: CborValue
    case n.controller.kind
    of nkUint:
      ctrl = canonNode(n.controller)
    of nkRange:
      if n.controller.lo.kind == nkUint and n.controller.hi.kind == nkUint and
          n.controller.lo.u == n.controller.hi.u:
        ctrl = canonNode(n.controller.lo)
      elif n.controller.lo.kind == nkUint and n.controller.hi.kind == nkUint:
        if n.controller.lo.u > n.controller.hi.u:
          raise cddlError("size range lower bound exceeds upper bound")
        ctrl = cborMap(
          (cborValue(uint64(0)), cborValue(uint64(13))),
          (cborValue(uint64(1)), canonIntLiteral(n.controller.lo)),
          (cborValue(uint64(2)), canonIntLiteral(n.controller.hi)),
          (cborValue(uint64(3)), cborValue(true)),
          (cborValue(uint64(4)), cborValue(true)),
        )
      else:
        raise cddlError("size range bounds must be integer literals")
    else:
      raise cddlError("size controller must be a uint literal or range")
    cborMap(
      (cborValue(uint64(0)), cborValue(uint64(14))),
      (cborValue(uint64(1)), cborValue("size")),
      (cborValue(uint64(2)), canonNode(n.target)),
      (cborValue(uint64(3)), ctrl),
    )

proc canonMember(m: CddlMember, isMap: bool): CborValue =
  if isMap and not m.hasKey:
    raise cddlError("map member missing key")
  if not isMap and m.hasKey:
    raise cddlError("array member must not have a key")
  if m.occ == occOptional and not isMap:
    raise cddlError("? occurrence not valid on array member")
  if m.occ == occUnbounded and isMap:
    raise cddlError("* occurrence not valid on map member")
  var pairs: seq[(CborValue, CborValue)]
  pairs.add((cborValue(uint64(0)), cborValue(uint64(10))))
  if m.hasKey:
    let mk = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(21))),
      (
        cborValue(uint64(1)),
        cborMap(
          (cborValue(uint64(0)), cborValue(uint64(6))),
          (cborValue(uint64(1)), cborValue("tstr")),
          (cborValue(uint64(2)), cborValue(m.key)),
        ),
      ),
    )
    pairs.add((cborValue(uint64(1)), mk))
  pairs.add((cborValue(uint64(2)), canonNode(m.ty)))
  if m.occ != occRequired:
    let occ = cborMap(
      (cborValue(uint64(0)), cborValue(uint64(11))),
      (cborValue(uint64(1)), cborValue(uint64(0))),
      (
        cborValue(uint64(2)),
        if m.occ == occOptional:
          cborValue(uint64(1))
        else:
          cborValue("unbounded"),
      ),
    )
    pairs.add((cborValue(uint64(3)), occ))
  cborMap(pairs)

proc canonicalizeImpl(rules: seq[CddlRule]): CborValue =
  # top-level rules sorted by rule name (§7.1)
  var rs = rules
  let nr = rs.len
  for i in 1 ..< nr:
    let key = rs[i]
    var j = i - 1
    while j >= 0 and rs[j].name > key.name:
      rs[j + 1] = rs[j]
      dec(j)
    rs[j + 1] = key
  # duplicate bound rule names are invalid
  for i in 1 ..< nr:
    if rs[i].name == rs[i - 1].name:
      raise cddlError("duplicate bound rule name: " & rs[i].name)
  var rulesArr: seq[CborValue]
  for r in rs:
    rulesArr.add(
      cborMap(
        (cborValue(uint64(0)), cborValue(uint64(1))),
        (cborValue(uint64(1)), cborValue(r.name)),
        (cborValue(uint64(3)), canonNode(r.body)),
      )
    )
  cborMap(
    (cborValue(uint64(0)), cborValue(uint64(0))),
    (cborValue(uint64(1)), cborArray(rulesArr)),
    (cborValue(uint64(2)), cborValue("cdcddle")),
  )

## Canonicalize a parsed rule set to the schema-as-data model. Errors are
## returned as a Result (never raised).
proc canonicalize*(rules: seq[CddlRule]): Result[CborValue, string] =
  try:
    ok(canonicalizeImpl(rules))
  except CddlError as e:
    err(e.msg)

## ---------------------------------------------------------------------------
## Public pipeline

## Parse + canonicalize + encode: source CDDL text to canonical schema bytes.
## Errors are returned as a Result (never raised).
proc encodeCddl*(src: string): Result[seq[byte], string] =
  let rules = parseCddl(src)
  if rules.isErr:
    return err(rules.error)
  let model = canonicalize(rules.get)
  if model.isErr:
    return err(model.error)
  ok(encodeCbor(model.get))

## ---------------------------------------------------------------------------
## Decoding and checking (spec §10)

proc mGet*(v: CborValue, k: uint64): CborValue =
  ## required integer-key lookup in a canonical model map
  if v.kind != ckMap:
    raise cddlError("expected a map, got " & $v.kind)
  for e in v.entries:
    if e[0].kind == ckUint and e[0].u == k:
      return e[1]
  raise cddlError("missing required key " & $k)

proc mGetOpt(v: CborValue, k: uint64): (bool, CborValue) =
  if v.kind != ckMap:
    return (false, nil)
  for e in v.entries:
    if e[0].kind == ckUint and e[0].u == k:
      return (true, e[1])
  return (false, nil)

proc checkName*(s: string): bool =
  validCddlName(s) and not isPrimitiveName(s)

proc checkGroup(g: CborValue, isMap: bool, refs: var seq[string]): bool

proc checkType*(v: CborValue, refs: var seq[string]): bool =
  ## validate one cdcddle-type node; returns true if valid
  if v.kind != ckMap:
    return false
  let kind = mGet(v, 0)
  if kind.kind != ckUint:
    return false
  case kind.u
  of 3:
    let name = mGet(v, 1)
    if name.kind != ckText or not checkName(name.s):
      return false
    refs.add(name.s)
    v.entries.len == 2
  of 5:
    let name = mGet(v, 1)
    if name.kind != ckText or not isPrimitiveName(name.s):
      return false
    v.entries.len == 2
  of 6:
    let lname = mGet(v, 1)
    let val = mGet(v, 2)
    if lname.kind != ckText:
      return false
    let kindOk =
      case lname.s
      of "uint":
        val.kind == ckUint
      of "nint":
        val.kind == ckNint
      of "bool":
        val.kind == ckBool
      of "tstr":
        val.kind == ckText
      of "bstr":
        val.kind == ckBytes
      else:
        false
    # no unknown extra fields on a literal node (§8)
    kindOk and v.entries.len == 3
  of 7, 8:
    let group = mGet(v, 1)
    if not checkGroup(group, kind.u == 8, refs):
      return false
    v.entries.len == 2
  of 12:
    let alts = mGet(v, 1)
    if alts.kind != ckArray or alts.items.len < 2:
      return false
    for a in alts.items:
      if not checkType(a, refs):
        return false
    v.entries.len == 2
  of 13:
    let lo = mGet(v, 1)
    let hi = mGet(v, 2)
    let incLo = mGet(v, 3)
    let incHi = mGet(v, 4)
    if lo.kind != ckMap or hi.kind != ckMap:
      return false
    if lo.entries[0][1].u != 6 or hi.entries[0][1].u != 6:
      return false
    if incLo.kind != ckBool or incLo.b != true or incHi.kind != ckBool or incHi.b != true:
      return false
    # a literal node is {0: 6, 1: name, 2: value}; the bound value is at index 2
    let loV = lo.entries[2][1]
    let hiV = hi.entries[2][1]
    # integer-literal bounds: uint or nint (§8 integer-literal = uint / nint)
    proc boundInt(x: CborValue): (bool, int64) =
      case x.kind
      of ckUint:
        (true, int64(x.u))
      of ckNint:
        (true, x.n)
      else:
        (false, 0)

    let (loOk, loI) = boundInt(loV)
    let (hiOk, hiI) = boundInt(hiV)
    if not loOk or not hiOk:
      return false
    if loI >= hiI:
      return false
    v.entries.len == 5
  of 14:
    let cname = mGet(v, 1)
    let target = mGet(v, 2)
    let ctrl = mGet(v, 3)
    if cname.kind != ckText or cname.s != "size":
      return false
    if not checkType(target, refs):
      return false
    if target.kind != ckMap or target.entries[0][1].u != 5:
      return false
    let tname = target.entries[1][1]
    if tname.kind != ckText or
        (tname.s != "uint" and tname.s != "tstr" and tname.s != "bstr"):
      return false
    # controller: uint literal or a non-negative inclusive range (§8: when
    # the controller is a range, both bounds MUST be non-negative)
    if ctrl.kind == ckMap and ctrl.entries[0][1].u == 6:
      if mGet(ctrl, 2).kind != ckUint:
        return false
    elif ctrl.kind == ckMap and ctrl.entries[0][1].u == 13:
      let clo = mGet(ctrl, 1)
      let chi = mGet(ctrl, 2)
      if clo.kind != ckMap or chi.kind != ckMap or clo.entries[0][1].u != 6 or
          chi.entries[0][1].u != 6:
        return false
      # literal value is at index 2 (index 1 is the literal name)
      let cloV = clo.entries[2][1]
      let chiV = chi.entries[2][1]
      if cloV.kind != ckUint or chiV.kind != ckUint:
        return false # both bounds non-negative
      if cloV.u >= chiV.u:
        return false
    else:
      return false
    v.entries.len == 4
  else:
    false

proc checkGroup(g: CborValue, isMap: bool, refs: var seq[string]): bool =
  if g.kind != ckMap:
    return false
  if g.entries[0][1].u != 9:
    return false
  let members = mGet(g, 1)
  if members.kind != ckArray:
    return false
  # an empty map group is valid (§8: a map group may have zero members)
  var prevKey = ""
  for m in members.items:
    if m.kind != ckMap or m.entries[0][1].u != 10:
      return false
    let (hasMk, mkv) = mGetOpt(m, 1)
    if isMap:
      if not hasMk:
        return false
      let keyNode = mkv
      if keyNode.kind != ckMap or keyNode.entries[0][1].u != 21:
        return false
      let lit = keyNode.entries[1][1]
      if lit.kind != ckMap or lit.entries[0][1].u != 6:
        return false
      let litVal = mGet(lit, 2)
      if litVal.kind != ckText or litVal.s == "":
        return false
      let k = litVal.s
      if k <= prevKey:
        return false # must be strictly sorted (duplicates invalid)
      prevKey = k
      # a map member may use the ? occurrence only; * is invalid (§8).
      # occurrence encoding: entries[1][1] = 0 (always); entries[2][1] =
      # uint 1 for optional, text "unbounded" for *.
      let (hasOcc, occv) = mGetOpt(m, 3)
      if hasOcc:
        let o = occv
        if o.kind != ckMap or o.entries[0][1].u != 11:
          return false
        if o.entries[1][1].kind != ckUint or o.entries[1][1].u != 0:
          return false
        if o.entries[2][1].kind != ckUint or o.entries[2][1].u != 1:
          return false # must be the ? (optional) occurrence
    else:
      if hasMk:
        return false # array members must not have keys
      let (hasOcc, occv) = mGetOpt(m, 3)
      if hasOcc:
        let o = occv
        if o.kind != ckMap or o.entries[0][1].u != 11:
          return false
        if o.entries[1][1].kind != ckUint or o.entries[1][1].u != 0:
          return false
        if o.entries[2][1].kind != ckText or o.entries[2][1].s != "unbounded":
          return false
        if members.items.len != 1:
          return false # homogeneous variable-length array
    let ty = mGet(m, 2)
    if not checkType(ty, refs):
      return false
    # no unknown keys
    for e in m.entries:
      if e[0].kind != ckUint or e[0].u notin {0, 1, 2, 3}:
        return false
  true

proc checkRule*(r: CborValue, refs: var seq[string], names: var seq[string]): bool =
  if r.kind != ckMap:
    return false
  if r.entries[0][1].u != 1:
    return false
  let name = mGet(r, 1)
  if name.kind != ckText or not checkName(name.s):
    return false
  for n in names:
    if n == name.s:
      return false # duplicate bound rule name
  names.add(name.s)
  let body = mGet(r, 3)
  if not checkType(body, refs):
    return false
  if r.entries.len != 3:
    return false
  true

## Logos prelude aliases: integer-width aliases that a schema may reference
## without a bound rule (commitment-model spec §5.1 prelude).
const PreludeAliasNames =
  ["uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64"]

proc isPreludeAlias(name: string): bool =
  for a in PreludeAliasNames:
    if name == a:
      return true
  false

## Decode and fully validate a canonical model byte string (§10).
## Raises CddlError / CborError; see `checkCanonical` for the Result form.
proc checkCanonicalImpl(bytes: openArray[byte]): CborValue =
  # deterministic-CBOR check first (§9): re-encode and compare
  if not validateDeterministic(bytes):
    raise cddlError("not deterministic CBOR")
  let doc = decodeCbor(bytes)
  if doc.kind != ckMap:
    raise cddlError("document is not a map")
  if doc.entries.len != 3:
    raise cddlError("document must have exactly 3 entries")
  let kind = mGet(doc, 0)
  if kind.kind != ckUint or kind.u != 0:
    raise cddlError("document kind must be 0")
  let id = mGet(doc, 2)
  if id.kind != ckText or id.s != "cdcddle":
    raise cddlError("unknown canonical-model identifier")
  let rules = mGet(doc, 1)
  if rules.kind != ckArray or rules.items.len == 0:
    raise cddlError("empty document rule array")
  # top-level rules must be in canonical (sorted) order (§7.1); duplicates are
  # rejected by checkRule, so the order must be strictly ascending
  var names: seq[string]
  var refs: seq[string]
  for i in rules.items.low() .. rules.items.high():
    if not checkRule(rules.items[i], refs, names):
      raise cddlError("invalid rule")
    if i > rules.items.low():
      if names[^1] <= names[^2]:
        raise cddlError("top-level rules not in canonical order")
  # every reference must resolve to a bound rule or a prelude alias
  for refName in refs:
    var found = isPreludeAlias(refName)
    if not found:
      for n in names:
        if n == refName:
          found = true
          break
    if not found:
      raise cddlError("unresolved reference: " & refName)
  result = doc

## Decode and fully validate a canonical model byte string (§10). Errors are
## returned as a Result (never raised) so a malformed canonical-model
## candidate cannot abort the runtime process (K10).
proc checkCanonical*(bytes: openArray[byte]): Result[CborValue, string] =
  try:
    ok(checkCanonicalImpl(bytes))
  except CddlError as e:
    err(e.msg)
  except CborError as e:
    err(e.msg)

## Full pipeline: source CDDL text to validated canonical schema bytes.
## Errors are returned as a Result (never raised).
proc canonicalizeCddl*(src: string): Result[seq[byte], string] =
  let bytes = encodeCddl(src)
  if bytes.isErr:
    return err(bytes.error)
  let chk = checkCanonical(bytes.get)
  if chk.isErr:
    return err(chk.error)
  ok(bytes.get)
