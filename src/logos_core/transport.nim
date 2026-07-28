# src/logos_core/transport.nim
# Per LOGOS-MODULE-TRANSPORT

import std/net, results, stew/[endians2, enums]

## Message kinds per LOGOS-MODULE-TRANSPORT §1.1
type TransportTag* = enum
  tHello = 0
  tRequest = 1
  tResponse = 2
  tSubscribe = 3
  tUnsubscribe = 4
  tEvent = 5
  tProtocolError = 6
  tCancel = 7

## A simple wrapper for a length-prefixed message.
## Per LOGOS-MODULE-TRANSPORT §2.1: 4-byte big-endian length prefix.
type TransportMessage* = object
  tag*: TransportTag
  payload*: seq[byte]

proc encodeMessage*(msg: TransportMessage): seq[byte] =
  ## Encodes a message with a 4-byte big-endian length prefix.
  result.add msg.payload.len.uint32.toBytesBE()

  # Append tag (1 byte)
  result.add(byte(msg.tag.ord))

  # Append payload
  result.add(msg.payload)

proc readExact*(
    client: Socket, dest: var openArray[byte], size: int
): Result[void, string] =
  ## Reads exactly `size` bytes from the socket.
  var read = 0
  while read < size:
    let chunk = client.recv(addr dest[read], size - read)
    if chunk <= 0:
      return err("Connection closed during read")
    read += chunk
  ok()

proc sendTransportMessage*(
    client: Socket, msg: TransportMessage
): Result[void, string] =
  ## Sends a length-prefixed TransportMessage over the socket.
  let bytes = encodeMessage(msg)
  var written = 0
  while written < bytes.len:
    let chunk = client.send(addr bytes[written], bytes.len - written)
    if chunk <= 0:
      return err("Failed to send transport message")
    written += chunk
  ok()

proc receiveTransportMessage*(client: Socket): Result[TransportMessage, string] =
  ## Receives and decodes a length-prefixed TransportMessage from the socket.
  # TODO this is not updated for the tag-in-message encoding and instead
  # places the tag "outside"
  var header: array[4, byte]
  ?readExact(client, header, 4)
  let length = uint32.fromBytesBE(header).int
  if length < 1:
    return err("Invalid transport frame length")

  var rawTag: array[1, byte]
  ?readExact(client, rawTag, 1)

  var tag: TransportTag
  if not tag.checkedEnumAssign(rawTag[0].int):
    return err("Unknown transport tag")

  var payload = newSeqUninit[byte](length)
  ?readExact(client, payload, length)

  ok TransportMessage(tag: tag, payload: payload)
