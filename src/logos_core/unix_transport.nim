# src/logos_core/unix_transport.nim
# The `logos.local.unix-stream` protected local-transport profile per
# LOGOS-MODULE-TRANSPORT §8.2, built on the stream binding (§2/§3), the
# route-ticket profile (§8.1.1), and the payload-commitment rules (§4.1).
#
# One connection carries one provider session:
#   1. The host creates a per-instance 0700 directory and binds a Unix
#      stream socket in it.
#   2. The caller connects to the exact path, sends a Hello carrying the
#      32-byte route ticket and the selected contract.
#   3. The host validates the Hello in the spec order (module -> token ->
#      schema), then atomically redeems the ticket, and returns a Hello
#      response (empty token).
#   4. The session carries Request/Response (with mandatory payload
#      commitments), Subscribe/Unsubscribe/SubscriptionResult, Event (with a
#      mandatory payload commitment), and Cancel.
#
# Peer identity: the host performs the spec's SO_PEERCRED / getpeereid()
# peer-identity check (TRANSPORT §8.2) — the connecting peer must be the same
# user as the host — in addition to the 0700 directory and the one-time route
# ticket as the authorization boundary.

import std/[net, os, strutils], results
from std/posix import SocketHandle, lstat, S_ISLNK, Stat
import ./cbor_profile, ./commitment, ./hash_profile, ./transport
import ./route_tickets, ./payload_commitment

## Raw POSIX Unix-domain-socket helpers (std/net's bindAddr/connect do not
## handle AF_UNIX paths in this toolchain).
when defined(posix):
  type SockaddrUn = object
    sun_family: c_ushort
    sun_path: array[108, char]

  func rawSocket(domain, typ, protocol: cint): cint {.importc: "socket".}
  func rawBind(fd: cint, a: pointer, addrlen: cint): cint {.importc: "bind".}
  func rawListen(fd: cint, backlog: cint): cint {.importc: "listen".}
  func rawConnect(fd: cint, a: pointer, addrlen: cint): cint {.importc: "connect".}
  func rawClose(fd: cint): cint {.importc: "close".}

  proc makeSockaddrUn(path: string): SockaddrUn =
    result.sun_family = AF_UNIX.c_ushort
    let n = min(path.len, 107)
    for i in 0 ..< n:
      result.sun_path[i] = path[i]
    result.sun_path[n] = '\0'

  proc bindUnixFd(fd: cint, path: string) =
    var sa = makeSockaddrUn(path)
    if rawBind(fd, addr(sa), sizeof(SockaddrUn).cint) < 0:
      raiseOSError(osLastError())

  proc connectUnixFd(fd: cint, path: string) =
    var sa = makeSockaddrUn(path)
    if rawConnect(fd, addr(sa), sizeof(SockaddrUn).cint) < 0:
      raiseOSError(osLastError())

  proc newUnixSocketFd(path: string, listening: bool): Socket =
    let fd = rawSocket(AF_UNIX.cint, SOCK_STREAM.cint, 0)
    if fd < 0:
      raiseOSError(osLastError())
    if listening:
      bindUnixFd(fd, path)
      if rawListen(fd, 16) < 0:
        discard rawClose(fd)
        raiseOSError(osLastError())
    else:
      connectUnixFd(fd, path)
    newSocket(SocketHandle(fd), AF_UNIX, SOCK_STREAM)

  ## Peer-identity check for the local profile (TRANSPORT §8.2): the connecting
  ## peer MUST be the same user as the host. Uses getsockopt(SO_PEERCRED) on
  ## the accepted socket (equivalent to getpeereid()).
  const SOL_SOCKET = 1
  const SO_PEERCRED = 17
  type Ucred = object
    pid: cint
    uid: c_ushort
    gid: c_ushort

  func getuid(): c_ushort {.importc: "getuid".}
  func rawGetsockopt(
    fd, level, optname: cint, optval, optlen: pointer
  ): cint {.importc: "getsockopt".}

  proc verifyPeerIdentity(client: Socket): bool =
    var ucred: Ucred
    var len: cint = sizeof(Ucred).cint
    if rawGetsockopt(
      cint(getFd(client)), SOL_SOCKET, SO_PEERCRED, addr(ucred), addr(len)
    ) < 0:
      return false
    ucred.uid == getuid()

const
  ## Protocol error codes (INTERFACE §: logos_error_code_t).
  errMethodNotFound* = 1
  errInvalidParams* = 2
  errModuleError* = 3
  errNotAuthorised* = 4
  errTransportError* = 5
  errTimeout* = 6
  errVersionMismatch* = 7
  errNotReady* = 8
  errCancelled* = 9

## The `logos.schema_commitment` value for a contract document: the pinned
## commitment-model / hash-profile / hash-suite identifiers plus the
## whole-schema root.
proc schemaCommitmentOf*(cddl: string): Result[SchemaCommitment, string] =
  let sr = ?schemaRootOf(cddl)
  ok(
    SchemaCommitment(
      commitmentModel: CommitmentModelRevision,
      schemaRoot: sr,
      hashProfile: HashProfileId,
      hashSuite: HashSuiteId,
    )
  )

## The dispatch callback a host uses to run one resolved method: it receives
## the bare method name and the decoded request params and returns the
## response value (in the response declaration's shape) or an error.
type UnixHostDispatch* =
  proc(methodName: string, params: CborValue): Result[CborValue, string] {.closure.}

type
  ## One active subscription on a provider session.
  Subscription = object
    subId: uint64
    event: string

  ## The `logos.local.unix-stream` host: one provider endpoint.
  UnixHost* = object
    listener: Socket
    baseDir*: string
    socketPath*: string
    expectedModule*: string
    expectedSchema*: SchemaCommitment
    contractCddl*: string
    ticketStore*: TicketStore
    dispatch*: UnixHostDispatch
    running*: bool

  ## The `logos.local.unix-stream` client: one provider session.
  UnixClient* = object
    socket: Socket
    established*: bool
    module*: string
    schema*: SchemaCommitment
    nextCallId*: uint64
    nextSubId*: uint64

# ============================================================================
# Host
# ============================================================================

proc newUnixHost*(
    baseDir: string,
    module: string,
    contractCddl: string,
    ticketStore: TicketStore,
    dispatch: UnixHostDispatch,
): Result[ref UnixHost, string] =
  ## Create the per-instance directory (0700), bind the Unix stream socket,
  ## and enter the listening state (TRANSPORT §8.2).
  let schema = ?schemaCommitmentOf(contractCddl)
  # Reject a pre-existing endpoint path; create a fresh 0700 directory.
  if dirExists(baseDir):
    return err("endpoint directory already exists: " & baseDir)
  try:
    createDir(baseDir)
    setFilePermissions(baseDir, {fpUserRead, fpUserWrite, fpUserExec})
  except CatchableError as e:
    return err("failed to create 0700 endpoint directory " & baseDir & " - " & e.msg)
  let sockPath = baseDir / "provider.sock"
  # reject a symlink at the endpoint path (TRANSPORT §8.2)
  when defined(posix):
    var st: Stat
    if lstat(sockPath.cstring, st) == 0 and S_ISLNK(st.st_mode):
      return err("endpoint path is a symlink: " & sockPath)
  if fileExists(sockPath):
    return err("endpoint path already exists: " & sockPath)
  var listener: Socket
  try:
    listener = newUnixSocketFd(sockPath, true)
  except CatchableError as e:
    return err("failed to bind unix socket " & sockPath & " - " & e.msg)
  let host = (ref UnixHost)(
    listener: listener,
    baseDir: baseDir,
    socketPath: sockPath,
    expectedModule: module,
    expectedSchema: schema,
    contractCddl: contractCddl,
    ticketStore: ticketStore,
    dispatch: dispatch,
    running: true,
  )
  ok(host)

proc stopUnixHost*(host: ref UnixHost) =
  if host == nil:
    return
  host.running = false
  try:
    host.listener.close()
  except:
    discard
  # remove the socket file (best effort)
  let p = host.socketPath
  try:
    removeFile(p)
  except:
    discard
  let d = host.baseDir
  try:
    removeDir(d)
  except:
    discard

## Send a ProtocolError when the connection is still writable, then close.
proc sendProtocolErrorAndClose(client: Socket, code: int, msg: string) =
  let pe = protocolError(code, msg)
  discard sendFramed(client, pe)
  try:
    client.close()
  except:
    discard

## Validate one Hello in the spec order (TRANSPORT §3.1) and atomically
## redeem the route ticket. Returns the redeemed record on success.
proc validateHello(
    host: ref UnixHost, client: Socket, hello: TMessage
): Result[TicketRecord, string] =
  # 1. module must equal the selected name
  if hello.module != host.expectedModule:
    sendProtocolErrorAndClose(client, errInvalidParams, "hello module mismatch")
    return err("not authorised")
  # 2. token: route-ticket validation (does NOT consume a live ticket)
  let vtRes = validateTicketLocal(
    host.ticketStore, hello.token, host.expectedModule, host.expectedSchema.schemaRoot
  )
  if vtRes.isErr:
    sendProtocolErrorAndClose(client, errNotAuthorised, "not authorised")
    return err("not authorised")
  var rec = vtRes.get
  # 3. schema must equal the selected contract
  if not commitmentEqual(hello.schema, host.expectedSchema):
    sendProtocolErrorAndClose(client, errVersionMismatch, "hello schema mismatch")
    return err("not authorised")
  # 4. atomically redeem (only one concurrent redemption succeeds); a
  # concurrent redemption that already consumed the ticket -> NOT_AUTHORISED
  let redeemRes = redeemTicket(host.ticketStore, rec.digest)
  if redeemRes.isErr:
    sendProtocolErrorAndClose(client, errNotAuthorised, "not authorised")
    return err("not authorised")
  ok(rec)

## Resolve + authorize + commitment-check one Request, then dispatch and
## commit the result. Sends the correlated Response (ok or error).
proc handleRequest(
    host: ref UnixHost, client: Socket, req: TMessage, rec: TicketRecord
): Result[void, string] =
  # Resolve the bare method name under the selected contract.
  let declsRes = methodDecls(host.contractCddl, req.methodName)
  if declsRes.isErr:
    discard
      sendFramed(client, responseError(req.callId, errMethodNotFound, declsRes.error))
    return ok()
  let (reqDecl, respDecl) = declsRes.get
  # Enforce the route's allowed method scope (RUNTIME §9.3): an absent list
  # permits every method; a present empty list permits none; a present list
  # permits the listed methods.
  let methodAllowed =
    if rec.access.methodsAbsent:
      true # absent: permit all
    else:
      req.methodName in rec.access.methods
  if not methodAllowed:
    discard
      sendFramed(client, responseError(req.callId, errNotAuthorised, "not authorised"))
    return ok()
  # Validate the mandatory request payload commitment.
  let expectedRes = computePayloadCommitment(host.contractCddl, reqDecl, req.params)
  if expectedRes.isErr:
    return err(expectedRes.error)
  let expected = expectedRes.get
  if cmpBytes(expected.schemaSubtreeRoot, req.requestCommitment.schemaSubtreeRoot) != 0 or
      cmpBytes(expected.valueRoot, req.requestCommitment.valueRoot) != 0:
    # a request-commitment mismatch MUST produce a ProtocolError + close
    # (TRANSPORT §4.1) — not a per-call response-err with the session
    # continuing.
    sendProtocolErrorAndClose(client, errInvalidParams, "request commitment mismatch")
    return ok()
  # Dispatch.
  let res = host.dispatch(req.methodName, req.params)
  if res.isErr:
    discard sendFramed(client, responseError(req.callId, errModuleError, res.error))
    return ok()
  let resultValue = res.get
  # Commit the result and send the ok Response.
  let resultCommitmentRes =
    computePayloadCommitment(host.contractCddl, respDecl, resultValue)
  if resultCommitmentRes.isErr:
    return err(resultCommitmentRes.error)
  let resultCommitment = resultCommitmentRes.get
  let resp = TMessage(kind: tkResponse)
  resp.respId = req.callId
  resp.isOk = true
  resp.result = resultValue
  resp.resultCommitment = resultCommitment
  ?sendFramed(client, resp)
  ok()

## Handle one provider session: the Hello handshake, then the directional
## message loop (TRANSPORT §3.1/§5/§6).
proc handleConnection(host: ref UnixHost, client: Socket) =
  try:
    # 1. the first message MUST be a Hello
    let firstRes = recvFramed(client)
    if firstRes.isErr:
      return
    let first = firstRes.get
    if first.kind != tkHello:
      sendProtocolErrorAndClose(client, errInvalidParams, "expected hello")
      return
    # 2. validate the Hello + redeem the ticket
    let recRes = validateHello(host, client, first)
    if recRes.isErr:
      return
    let rec = recRes.get
    # 3. Hello response (empty token; same selected contract)
    let helloResp = TMessage(kind: tkHello)
    helloResp.module = host.expectedModule
    helloResp.token = @[]
    helloResp.schema = host.expectedSchema
    if sendFramed(client, helloResp).isErr:
      return
    # 4. directional message loop
    var subs: seq[Subscription] = @[]
    while host.running:
      let msgRes = recvFramed(client)
      if msgRes.isErr:
        # a framing/envelope validation failure MUST send a ProtocolError
        # before close (TRANSPORT §2.1); a clean EOF makes the send fail
        # harmlessly.
        sendProtocolErrorAndClose(client, errTransportError, "framing error")
        return
      let msg = msgRes.get
      case msg.kind
      of tkRequest:
        if handleRequest(host, client, msg, rec).isErr:
          break
      of tkSubscribe:
        # enforce the route's allowed event scope (RUNTIME §9.3): an absent
        # list permits every event; a present empty list permits none.
        let eventAllowed =
          if rec.access.eventsAbsent:
            true # absent: permit all
          else:
            msg.event in rec.access.events
        if not eventAllowed:
          let sr = TMessage(kind: tkSubscriptionResult)
          sr.resultId = msg.subId
          sr.operation = 3
          sr.resultIsOk = false
          sr.resultError =
            ErrorPayload(code: errNotAuthorised, message: Opt.some("not authorised"))
          discard sendFramed(client, sr)
        else:
          subs.add(Subscription(subId: msg.subId, event: msg.event))
          let sr = TMessage(kind: tkSubscriptionResult)
          sr.resultId = msg.subId
          sr.operation = 3
          sr.resultIsOk = true
          discard sendFramed(client, sr)
      of tkUnsubscribe:
        var found = false
        for i in countdown(subs.len - 1, 0):
          if subs[i].subId == msg.unsubId:
            subs[i] = subs[subs.high()]
            subs.setLen(subs.len - 1)
            found = true
            break
        let sr = TMessage(kind: tkSubscriptionResult)
        sr.resultId = msg.unsubId
        sr.operation = 4
        sr.resultIsOk = found
        if not found:
          sr.resultError = ErrorPayload(
            code: errInvalidParams, message: Opt.some("unknown subscription")
          )
        discard sendFramed(client, sr)
      of tkCancel:
        # a Cancel with an unknown id MUST be silently ignored (TRANSPORT §6);
        # the POC handles requests synchronously, so no id is ever in-flight.
        discard
      of tkProtocolError:
        return
      else:
        # a Hello after establishment, or any other out-of-role message
        sendProtocolErrorAndClose(client, errInvalidParams, "unexpected message")
        return
  except CatchableError:
    discard
  try:
    client.close()
  except:
    discard

## Accept one connection and serve the session to completion (POC:
# synchronous, single-connection service).
proc serveOne*(host: ref UnixHost): bool =
  var client: Socket
  try:
    host.listener.accept(client)
  except OSError:
    return false
  # Verify the peer's identity before the handshake (TRANSPORT §8.2).
  if not verifyPeerIdentity(client):
    sendProtocolErrorAndClose(client, errNotAuthorised, "peer identity check failed")
    return true
  handleConnection(host, client)
  true

## Serve connections in a loop until the host is stopped (POC: synchronous,
# one session at a time).
proc serveLoop*(host: ref UnixHost) =
  while host.running:
    if not serveOne(host):
      break

## Publish one Event to a subscribed client on this session. The caller must
## hold the client socket for the session; the event value is committed under
## the event declaration (TRANSPORT §5).
proc sendEvent(
    client: Socket,
    contractCddl: string,
    eventDecl: string,
    subId: uint64,
    eventName: string,
    data: CborValue,
): Result[void, string] =
  let commitmentRes = computePayloadCommitment(contractCddl, eventDecl, data)
  if commitmentRes.isErr:
    return err(commitmentRes.error)
  let commitment = commitmentRes.get
  let ev = TMessage(kind: tkEvent)
  ev.eventSub = subId
  ev.eventName = eventName
  ev.data = data
  ev.eventCommitment = commitment
  sendFramed(client, ev)

# ============================================================================
# Client
# ============================================================================

proc connectUnixClient*(
    socketPath: string, module: string, ticket: seq[byte], schema: SchemaCommitment
): Result[ref UnixClient, string] =
  ## Connect to the exact socket path and complete the Hello handshake
  ## (TRANSPORT §3.1/§8.2). The ticket is disclosed in the first Hello.
  var socket: Socket
  try:
    socket = newUnixSocketFd(socketPath, false)
  except CatchableError as e:
    return err("failed to connect to " & socketPath & " - " & e.msg)
  # send the Hello
  let hello = TMessage(kind: tkHello)
  hello.module = module
  hello.token = ticket
  hello.schema = schema
  if sendFramed(socket, hello).isErr:
    socket.close()
    return err("failed to send hello")
  # receive + validate the Hello response
  let respRes = recvFramed(socket)
  if respRes.isErr:
    socket.close()
    return err("no hello response: " & respRes.error)
  let resp = respRes.get
  if resp.kind != tkHello:
    socket.close()
    return err("expected hello response")
  if resp.module != module:
    socket.close()
    return err("hello response module mismatch")
  if not commitmentEqual(resp.schema, schema):
    socket.close()
    return err("hello response schema mismatch")
  let client =
    (ref UnixClient)(socket: socket, established: true, module: module, schema: schema)
  ok(client)

proc closeUnixClient*(client: ref UnixClient) =
  if client == nil:
    return
  try:
    client.socket.close()
  except:
    discard
  client.established = false

## Send one Request with a mandatory payload commitment and receive the
## correlated Response, verifying the result commitment (TRANSPORT §4.1).
proc callUnixClient*(
    client: ref UnixClient, contractCddl: string, methodName: string, params: CborValue
): Result[CborValue, string] =
  if not client.established:
    return err("client not established")
  let declsRes = methodDecls(contractCddl, methodName)
  if declsRes.isErr:
    return err(declsRes.error)
  let (reqDecl, respDecl) = declsRes.get
  let commitmentRes = computePayloadCommitment(contractCddl, reqDecl, params)
  if commitmentRes.isErr:
    return err(commitmentRes.error)
  let commitment = commitmentRes.get
  let req = TMessage(kind: tkRequest)
  req.callId = client.nextCallId
  req.methodName = methodName
  req.params = params
  req.requestCommitment = commitment
  inc client.nextCallId
  ?sendFramed(client.socket, req)
  let respRes = recvFramed(client.socket)
  if respRes.isErr:
    return err("no response: " & respRes.error)
  let resp = respRes.get
  if resp.kind != tkResponse:
    return err("expected response")
  if resp.respId != req.callId:
    return err("response id mismatch")
  if resp.isOk:
    # verify the mandatory result commitment
    let expectedRes = computePayloadCommitment(contractCddl, respDecl, resp.result)
    if expectedRes.isErr:
      return err(expectedRes.error)
    let expected = expectedRes.get
    if cmpBytes(expected.schemaSubtreeRoot, resp.resultCommitment.schemaSubtreeRoot) != 0 or
        cmpBytes(expected.valueRoot, resp.resultCommitment.valueRoot) != 0:
      return err("result commitment mismatch")
    ok(resp.result)
  else:
    let code = resp.error.code
    let msg = if resp.error.message.isSome: resp.error.message.get else: ""
    err("call failed (code " & $code & "): " & msg)

## Send a Subscribe and receive the correlated SubscriptionResult.
proc subscribeUnixClient*(
    client: ref UnixClient, event: string
): Result[uint64, string] =
  if not client.established:
    return err("client not established")
  let subId = client.nextSubId
  inc client.nextSubId
  let sub = TMessage(kind: tkSubscribe)
  sub.subId = subId
  sub.event = event
  ?sendFramed(client.socket, sub)
  let resRes = recvFramed(client.socket)
  if resRes.isErr:
    return err("no subscription result: " & resRes.error)
  let sr = resRes.get
  if sr.kind != tkSubscriptionResult:
    return err("expected subscription result")
  if sr.resultId != subId:
    return err("subscription result id mismatch")
  if not sr.resultIsOk:
    let code = sr.resultError.code
    return err("subscription failed (code " & $code & ")")
  ok(subId)

## Send an Unsubscribe and receive the correlated SubscriptionResult.
proc unsubscribeUnixClient*(
    client: ref UnixClient, subId: uint64
): Result[void, string] =
  if not client.established:
    return err("client not established")
  let unsub = TMessage(kind: tkUnsubscribe)
  unsub.unsubId = subId
  ?sendFramed(client.socket, unsub)
  let resRes = recvFramed(client.socket)
  if resRes.isErr:
    return err("no subscription result: " & resRes.error)
  let sr = resRes.get
  if sr.kind != tkSubscriptionResult:
    return err("expected subscription result")
  if sr.resultId != subId:
    return err("subscription result id mismatch")
  if not sr.resultIsOk:
    return err("unsubscribe failed")
  ok()

## Receive one Event and verify its mandatory payload commitment.
proc recvUnixEvent*(
    client: ref UnixClient, contractCddl: string, eventDecl: string
): Result[(uint64, string, CborValue), string] =
  if not client.established:
    return err("client not established")
  let evRes = recvFramed(client.socket)
  if evRes.isErr:
    return err("no event: " & evRes.error)
  let ev = evRes.get
  if ev.kind != tkEvent:
    return err("expected event")
  # verify the mandatory event payload commitment
  let expectedRes = computePayloadCommitment(contractCddl, eventDecl, ev.data)
  if expectedRes.isErr:
    return err(expectedRes.error)
  let expected = expectedRes.get
  if cmpBytes(expected.schemaSubtreeRoot, ev.eventCommitment.schemaSubtreeRoot) != 0 or
      cmpBytes(expected.valueRoot, ev.eventCommitment.valueRoot) != 0:
    return err("event commitment mismatch")
  ok((ev.eventSub, ev.eventName, ev.data))
