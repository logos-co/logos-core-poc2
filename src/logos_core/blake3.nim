## BLAKE3-256 (Logos mandatory hash suite: `logos.hash-suite.blake3-256`)
##
## Ordinary unkeyed BLAKE3, 32-byte digest (first 32 bytes of the
## extendable output), no context string.
##
## Delegates to the BLAKE3 C implementation via the `blake3_c` package
## (https://github.com/arnetheduck/nim-blake3-c).
##
## Per LOGOS-MODULE-HASH-PROFILE §6.1:
## - digest length: 32 bytes
## - mode: ordinary unkeyed hashing
## - no keyed hashing, no key derivation, no context string

import blake3_c

## 32-byte BLAKE3 digest of `data` (unkeyed, no context string).
proc blake3_256*(data: openArray[byte]): array[0 .. 31, byte] =
  var h: Blake3Hasher
  h.init()
  if data.len > 0:
    h.update(data[0].addr, csize_t(data.len))
  h.finalize(result[0].addr, csize_t(result.len))
