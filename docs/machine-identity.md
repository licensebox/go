# Machine identity

Licensebox checks two independent pieces of software state: the installation's
Ed25519 private key and a product-specific binding derived from native host
identity. The binding is included in the server-signed v2 lease and in signed
activation, token-polling and app-call proofs. The SDK compares it with the
current host before using a cached lease, including offline.

## Native sources

| Platform | Source |
| --- | --- |
| Linux | DMI system UUID where readable, then an ARM device-tree serial, then the system machine-id (including D-Bus fallback) |
| Windows | System UUID in SMBIOS Type 1, read through GetSystemFirmwareTable |
| macOS | IOPlatformUUID, read through the system ioreg binary |

The SDK sends only a versioned source label and HMAC-SHA-256 digest scoped to
the product. Raw identifiers are neither saved in the credential folder nor
transmitted. Product scoping prevents directly correlating the digest across
products. The HMAC namespace is an application-specific derivation key, not a
secret that authenticates the physical host.

No network address, hostname, MAC address, CPU count, memory capacity, or random
installation token stands in for a missing native identity. Missing or invalid
identity fails closed. Linux firmware files may require privileges; machine-id
is the fallback for ordinary users. It identifies an OS installation and can
be copied in a badly prepared image. Changing identity or which source is
readable can require activation again. Firmware UUIDs may also be duplicated
by hypervisors or vendors.

## Binding format for other languages

Canonicalize the native identifier by trimming terminal NUL bytes and whitespace,
lowercasing, and removing UUID hyphens. It must decode as 16 bytes of hex for UUID
and machine-id sources; device-tree serials may decode as 8–32 bytes. All-zero
and all-FF identifiers are rejected. Windows uses the UUID bytes as stored in the
SMBIOS table. Source names are the exact labels in `machine.go`.

```text
key = SHA256(UTF8("licensebox machine binding v1\n" + product))
digest = HMAC_SHA256(key, UTF8(source + "\n" + canonical_identifier))
binding = "m1:" + source + ":" + lowercase_hex(digest)
```

The binding format is m1; leases and signed request proofs are v2. Source and
OS changes can produce a different identity, including a dual-boot OS with a
different native source. A system reinstall that resets machine-id can also
require activation. Ordinary app reinstalls preserve the native identifier.

## Copying, reinstalling and revoking

- Copying credentials alone to another ordinary host fails locally, before an
  online renewal or offline operation. It does not silently sign in or transfer
  a seat.
- Explicit SignIn on the new host rotates a copied installation key, completes
  email activation and lets the server apply the product's seat policy.
- Reinstalling the app with an unchanged native identity replaces that host's existing seat
  atomically, preserving other machines' seats. A displaced old key cannot
  silently reclaim its allocation.
- Machine revocation follows the native binding within the product as well as
  the key. Deleting local credentials and generating a key does not lift it.
- The server refuses changing a registered key's binding. Registration and
  activity updates cannot clear an administrative revocation through stale
  read/modify/write state.

Protocol v2 is a breaking change. V1 clients and leases do not support these
proofs. Updating requires one activation to issue a bound v2 lease. Already
issued v1 leases can remain usable in old binaries until their offline expiry.

## Security boundary

These checks detect ordinary credential-folder copying. The native identifiers
are assertions made by the OS, not remote hardware attestations. An attacker
controlling the host, a fully cloned VM with identical IDs, or a modified
binary can spoof them. TPM/Secure Enclave key attestation is not implemented.
Do not advertise these bindings as an uncopyable or tamper-proof machine ID.

## Sources

- [systemd machine-id guidance](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html)
- [Microsoft GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable)
- [Apple IOPlatformExpertDevice](https://developer.apple.com/documentation/kernel/ioplatformexpertdevice)
- [DMTF SMBIOS specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.8.0.pdf)
