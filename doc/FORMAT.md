# cljpass – Format Specification v1

Status: Draft 1 · Language of the specification: English · Keywords MUST/SHOULD/MAY as in RFC 2119.

## 1. Goals and threat model

cljpass is a team password store with **per-entry permissions** (like Passbolt) and a **file-based, offline-capable architecture** (like KeePass).

| Goal | Implementation |
|---|---|
| Storage is untrusted (HTTP object store, local cache, backup) | Contents encrypted, everything signed, clients verify for themselves |
| Read only with permission | Entry keys are sealed only for those entitled |
| Write/share only with permission | Every version is signed. Clients accept it only if the author had the permission according to the previous ACL |
| Admins do not see passwords | Admins only sign the roster (users, groups). They have neither entry keys nor group keys |
| No DC needed in operation | AD is only the source for the roster (sync). Unlocking and reading are entirely local |
| Offline | Reading from the local state. Writes are queued and applied later (§9) |
| No key handling for users | The identity is created automatically and protected by OS means (DPAPI, Keychain/Secure Enclave) |

**Attackers the format protects against:** anyone who reads or modifies the storage, a malicious member without the appropriate permission, a compromised admin PC (for entry contents only), rollback to older states the client has already seen.

**Not covered:**
- A compromised end device of an entitled user.
- The holder of the org recovery key. They can recover all identities, and the key MUST be stored offline and split (§10).
- Deletion of files. Backups help against this, and deletion is detectable, see §8.
- Anyone who was once allowed to read may have memorized values. After a permission is revoked, the password SHOULD be changed.

## 2. Cryptographic primitives

The selection is deliberately limited to what **Apple CryptoKit**, **WebCrypto** and **Java JCA** support without additional libraries.

| Purpose | Algorithm | Encoding |
|---|---|---|
| Signature | Ed25519 (RFC 8032) | public key: 32 bytes raw; signature: 64 bytes |
| Key agreement | X25519 (RFC 7748) | 32 bytes raw |
| Key derivation | HKDF-SHA256 (RFC 5869) | – |
| Symmetric | AES-256-GCM, 96-bit nonce, 128-bit tag | `ct` = ciphertext ‖ tag |
| Hash | SHA-256 | hex, lowercase |
| One-time codes | PBKDF2-HMAC-SHA256, 600 000 iterations | – |

All binary values are encoded as Base64 (RFC 4648 §4, with padding).
Nonces MUST come from a cryptographically secure random number generator. A key is used for at most one message, except for the process memory key (§11).

### 2.1 Sealed box (encrypting for a public key)

```
seal(R_pub, plaintext, aad):
  (e_priv, e_pub) = X25519 key pair, fresh
  shared = X25519(e_priv, R_pub)
  k      = HKDF-SHA256(ikm=shared, salt=e_pub ‖ R_pub, info="cljpass seal v1", L=32)
  n      = 12 random bytes
  ct     = AES-256-GCM(k, n, plaintext, aad)
  → {"epk": b64(e_pub), "n": b64(n), "ct": b64(ct)}
```

A `shared` consisting only of zero bytes MUST be rejected (low-order points).
`aad` binds every ciphertext to its context (§6), so that it cannot be moved into another entry or another version.

## 3. Encoding

Every file is UTF-8 JSON in **canonical form**, a subset of RFC 8785 (JCS):
- Object keys sorted by UTF-16 code units. All keys are ASCII in `snake_case`.
- No whitespace.
- Numbers only as integers in the range 0 … 2^53−1. Floating-point numbers are forbidden.
- `null` is not written; missing fields mean "not set". Exception: `prev` in the first version (§5, §6).
- Arrays with set semantics (members, ACL, wraps) are sorted in ascending order, see the sort key at the respective field.
- Objects only have fixed field names. Data such as user names never appear as keys, but always in arrays of objects. This simplifies Swift `Codable` and the TypeScript types.

`H(x)` = SHA-256 over the canonical bytes of `x`, as hex.

### 3.1 Names

`user` and `group` follow `^[a-z0-9][a-z0-9._-]{0,63}$`. They are **lowercase**, because AD account names are case-insensitive.
A principal is `u:<user>` or `g:<group>`. The wrap key of a group additionally carries the epoch: `g:<group>#<epoch>`.

### 3.2 Signed envelope

```json
{"body":{…},"sig":"<b64>","signer":"alice","type":"entry","v":1}
```

`sig = Ed25519-Sign(signer_key, canonical({"body":…,"signer":…,"type":…,"v":1}))`

The type is part of the signature (domain separation). A verifier MUST specify the expected `type` and take the key of the `signer` from the respective authoritative source (§4–§7), never from the document itself. The only exception is self-signed requests.

Types: `org`, `roster`, `request`, `escrow`, `group_key`, `group_wrap`, `entry`.

## 4. Object tree

The tree is the same for all transports (§9):

```
org.json                                  trust anchor
roster/00000001.json …                    roster chain (admins)
requests/<user>.json                      enrollment requests (self-signed)
escrow/<user>.json                        identity sealed for the recovery key
groups/<group>/<epoch>/key.json           public group key of an epoch
groups/<group>/<epoch>/wrap-<user>.json   private group key for a member
entries/<uuid>/00000001.json …            entry versions
```

Version files have 8-digit numbers with leading zeros. Objects under `roster/`, `groups/` and `entries/` are **immutable**: they are only created, never overwritten (§9).

### 4.1 `org.json` (type `org`)

```json
{"admins":[{"sign_pub":"…","user":"admin"}],"name":"Example Ltd",
 "org_id":"<uuid>","recovery_pub":"…"}
```

- Signed by one of the `admins`.
- Clients **pin** `H(body)` during setup. This happens via GPO or MDM, together with the storage location.
- If the hash differs, the client MUST reject the vault.
- Changing admins means a new `org.json` and a new pin. This is deliberately cumbersome.

## 5. Roster

`roster/<n>.json`, type `roster`, signed by an admin from `org.json`:

```json
{"groups":[{"deleted":false,"epoch":2,"group":"it","members":["bob","dave"],"source":"ad"}],
 "org_id":"…","prev":"<H(body n-1)>|null","users":[
  {"box_pub":"…","display_name":"Bob B.","sign_pub":"…","status":"active","user":"bob"}],
 "version":2}
```

- Sorting: `users` by `user`, `groups` by `group`, `members` ascending.
- Rules:
  - **R1** `version` = file number.
  - **R2** `prev` = `H(body)` of version n−1; for n = 1, `prev` is `null`.
  - **R3** `org_id` matches `org.json`.
  - **R4** The signature comes from an admin.
  - If a rule is violated, the client MUST stop at that point. The roster is the root of all permissions; a gap in it is not skipped.
- `status` ∈ {`active`, `disabled`}. Only `active` users may sign, where the roster of the respective version always applies (§6).
- **Epoch:** When a member is removed from a group, the admin MUST increase `epoch`. A new group starts with `epoch` 1.
- **Anti-rollback:** The client stores the highest roster version it has seen. If the newest version is lower, it MUST stop.

## 6. Entries

`entries/<uuid>/<n>.json`, type `entry`, signed by the author:

```json
{"acl":[{"perm":"owner","principal":"u:alice"},{"perm":"read","principal":"g:it"}],
 "author":"alice","created_at":"2026-09-25T10:00:00Z",
 "data":{"ct":"…","n":"…"},"deleted":false,"entry_id":"<uuid>",
 "prev":"<H(body of the previous version)>|null","roster_version":7,"version":3,
 "wraps":[{"box":{"ct":"…","epk":"…","n":"…"},"principal":"g:it#2"},
          {"box":{…},"principal":"u:alice"}]}
```

**Permissions:** `read` < `update` < `owner`.
The effective permission of a user U on an ACL under roster R is the maximum of their direct entry `u:U` and all entries `g:G` where U is a member of G according to R. If U is not `active` in R, they have no permission.

**Encryption of each version:**
1. New random key `K` (32 bytes).
2. `data = AES-GCM(K, canonical(payload), aad="entry:<uuid>:<version>")`.
3. One wrap for each principal of the ACL:
   - `u:X` → `seal(box_pub of X, K, aad="entry-key:<uuid>:<version>:u:X")`
   - `g:G` → `seal(key.box_pub of the current epoch e of G, K, aad="entry-key:<uuid>:<version>:g:G#e")`
4. The set of wraps MUST correspond exactly to the ACL. A wrap for someone not in the ACL is a rule violation (E7).

**Payload** (exists only in encrypted form):

```json
{"custom_fields":[{"name":"PIN","protected":true,"value":"1234"}],
 "expires":"","folder":"Server/Linux","notes":"","password":"…",
 "tags":"linux;prod","title":"DB prod","url":"https://…","username":"root"}
```

Unknown fields MUST be preserved when editing (forward compatibility).

- `tags`: tags as in KeePass, normalized to `a;b` (input separated by `;` or `,`, without spaces and duplicates). If the field is missing, `""` applies.
- Attachments and the KeePass history are in `kdbx` (§6.3). An entry created in cljpass gets a `kdbx.entry` with its first attachment.
- TOTP is stored in a custom field: `otp` (otpauth URI, KeePassXC), `TimeOtp-Secret-Base32` etc. (KeePass 2.47+) or `TOTP Seed`/`TOTP Settings`. Clients only show the current code, never the secret.

### 6.1 Validation rules

For each version file in ascending number order. `P` is the last **valid** predecessor, `R` = Roster[`roster_version`].

| Rule | Condition |
|---|---|
| E1 | `version` = file number, `entry_id` = directory name |
| E2 | `R` exists; `roster_version` ≤ newest roster version; ≥ `P.roster_version` |
| E3 | `author` = `signer` is `active` in `R`, and the signature is valid with `sign_pub` from `R` |
| E4 | ACL not empty, at least one `owner`, all `perm` valid, principals syntactically valid |
| E5 | first valid version: `prev` = null and `u:<author>` is `owner` |
| E6 | otherwise: `prev` = `H(P.body)`; required permission of the author on `P.acl` under `R`: `owner` if `acl` or `deleted` change, otherwise `update` |
| E7 | the set of wrap principals corresponds to the ACL (groups with the epoch from `R`) |

**Invalid versions** are **skipped and reported**, not treated as fatal. Otherwise someone with read permission could make an entry unusable for everyone by writing a garbage file.
- The head is the last valid version.
- The next write number is `max(file number) + 1`, with `prev` = `H(head)`.

**Warnings**, which are displayed visibly:
- W1: There are skipped versions ("invalid change by bob discarded").
- W2: The author of the head would no longer have the required permission under the *current* roster (e.g. removed in the meantime).
- W3: The ACL contains disabled users. Recommendation: change the password.

**Anti-rollback:** The client stores the highest valid version seen per entry. If the head is lower, an error message "Rollback detected" appears, and nothing is shown.

### 6.2 Operations

| Action | required permission | effect |
|---|---|---|
| create | – (any `active` user) | v1, ACL = {`u:me`: owner} |
| edit | update | new version, same ACL, new `K` |
| share / change permission / revoke | owner | new version with new ACL, new `K` only for the new ACL |
| delete | owner | new version with `deleted`: true and empty payload `{}` |
| duplicate | read | new entry, creator is owner |

A client MUST check every version it wants to write against §6.1 itself beforehand.

### 6.3 KeePass (KDBX)

An import from KeePass MUST be lossless: what was in the file is in it again after an export.

**Entry.** Every KeePass entry becomes an entry. The standard fields `Title`, `UserName`, `Password`, `URL` and `Notes` become `title`, `username`, `password`, `url` and `notes`. The group path below the root becomes `folder` (names joined with `/`). A set expiry date becomes `expires` (`YYYY-MM-DD`, UTC), `<Tags>` becomes `tags`. All other fields become `custom_fields`, with `protected` from the `Protected` attribute. In addition:

```json
"kdbx":{"v":1,"db":"<import ID>","pos":0,
        "entry":"<Entry>…</Entry>",
        "groups":[["<group UUID>","Company"],["<UUID>","Server"]],
        "icon":{"id":0,"custom":"<icon UUID>"},
        "icons":[{"uuid":"<icon UUID>","xml":"<Icon>…</Icon>"}],
        "binaries":[{"ref":"0","protected":true,"data":"<base64>"}]}
```

- `entry` is the complete `<Entry>` element including history. Protected values are stored in it as plaintext (the whole payload is encrypted), timestamps as ISO 8601.
- `binaries` contains the attachments that `entry` references via `Ref`; `icons` the custom icons used by the entry or its history.
- `pos` is the position in the group, `groups` the path from the root.

**Database.** Additionally, an entry with `kdbx_db` is created: `{"v":1,"id":"<import ID>","skeleton":"<KeePassFile>…</KeePassFile>","public_custom_data":"<base64>","version":"4.1","source":"…","imported_at":"…"}`. `skeleton` is the document without entries: Meta (settings, custom icons, `CustomData` of plugins), the group tree (including empty groups) and `DeletedObjects`.

**Export.** The client builds the file from `skeleton` and the entries it is allowed to read.
- The vault fields win. If they differ from `entry`, the previous state is appended to the history and `LastModificationTime` is set.
- An entry ends up in its original group as long as `folder` matches it, otherwise in the folder path (missing groups are created).
- Payload fields without a KeePass counterpart are stored as canonical JSON in the `CustomData` item `cljpass/payload` and restored on the next import.
- KDBX 4.0 is written, or 4.1 if the document contains elements from 4.1. Cipher is AES-256, key derivation Argon2id.
- As in KeePass, the history per entry is limited to `Meta/HistoryMaxItems` (default 10, `-1` = unlimited); the oldest states are dropped.
- Changing attachments (adding, replacing, removing), restoring an older version or deleting a history item changes `entry` directly. As in KeePass, the previous state is put into the history and `LastModificationTime` is set. Attachment data referenced neither by the entry nor by its history is dropped.

Unknown elements in `entry` and `skeleton` MUST be preserved unchanged.

## 7. Group keys

Each group has one X25519 key pair per epoch. It is generated by **a member**, not by the admin.

`groups/<g>/<e>/key.json`, type `group_key`: `{"box_pub":"…","epoch":e,"group":"g","roster_version":R}`
`groups/<g>/<e>/wrap-<u>.json`, type `group_wrap`:
`{"box":seal(box_pub of u, priv_raw, aad="group:<g>:<e>:<u>"),"epoch":e,"group":"g","roster_version":R,"user":"u"}`

`roster_version` is the roster version under which the document was created.

| Rule | Condition |
|---|---|
| G1 | In roster `R` = Roster[`roster_version`], `e` is the current epoch of g, and the signer is an active member of g in `R`. `R` ≤ newest roster version |
| G2 | `group`, `epoch` and `user` match the path. For a wrap, `user` is a member of g in `R` |
| G3 | At the recipient, the unwrapped private key matches `key.box_pub`. Check: seal and open a probe, or derive the public key from it |

**Maintenance** (every client of a member, on every sync):
1. If `key.json` is missing for the current epoch: generate a key pair, create `key.json`, then immediately create your own `wrap`. On a conflict (§9) the first writer wins.
2. If the client can open the current group key: create a `wrap` for every active member without one.

G1 deliberately refers to the roster at the time of creation, not the current one. Otherwise, removing the member who created an epoch would make all entries of that epoch unreadable for the remaining members. A removed member can thus only create wraps for old epochs. They know those keys anyway.

**Consequences:**
- A new member immediately gets access to all entries of the group, without entries being re-encrypted. This is better than in Passbolt.
- A removed member can no longer read anything new from the new epoch on.
- Entries that still refer to old epochs SHOULD be re-encrypted by someone with write permission. W3 applies accordingly: change the password.
- Anyone who wants to share with a group whose current epoch does not yet have a `key.json` gets the message "Group not ready yet". Falling back to an older epoch is FORBIDDEN, because that would include removed members again.

## 8. Enrollment and identity

**Identity** (only locally and in escrow): `{"box":{"priv":…,"pub":…},"sign":{"priv":…,"pub":…},"user":"alice"}`. The private keys are 32 bytes raw.

1. The client generates the identity and protects it locally: Windows DPAPI (CurrentUser), iOS Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, optionally Secure Enclave or Face ID.
2. It writes `requests/<user>.json` (type `request`, self-signed: `{"box_pub","sign_pub","user"}`). This file may be overwritten.
3. Then it writes `escrow/<user>.json` (type `escrow`, signed with the key from the request: `{"box":seal(recovery_pub, canonical(identity), aad="escrow:<user>"),"user"}`). The order matters, because the server checks the escrow against the key of the request.
4. An admin takes the request into the roster after comparing the **fingerprint**. The fingerprint consists of the first 16 bytes of SHA-256(`sign_pub`), as hex in groups of 4. The user's client displays it, and the user tells it to the admin, e.g. on the phone.
   - If the fingerprint does not match, approval MUST fail. This way nobody can submit a request in someone else's name.
   - A new request with a new key for an existing user (new device without transfer) is handled the same way and is marked in the list.

**New device:** The transfer from an existing device works via a file or a QR code with
`{"box":AES-GCM(PBKDF2(code,salt,600000), identity, aad="transfer:<user>"),"format":"cljpass-transfer-v1","iterations":…,"salt":…,"user":…}`.
The user types in the 80-bit one-time code (16 characters from 32 symbols) once.

### 8.1 Setup with the Windows login (Kerberos, optional)

If the server is started with a keytab and the client has `{:kerberos true}` (from `org.edn` or via the checkbox in the setup dialog), Kerberos replaces the fingerprint comparison by phone. Without these settings, §8 applies unchanged.

1. The client generates the identity as in §8 and sends `request` and `escrow` in **one** request:
   `POST /v1/enroll` with `Authorization: Negotiate <SPNEGO token>` and the body `{"request":"<document>","escrow":"<document>"}`. Windows obtains the ticket itself (SSPI); the user enters nothing.
2. The server checks the ticket with its keytab and derives the user from the principal: `alice@EXAMPLE.LOCAL` → `alice`. It only accepts principals of the configured realm, no service principals (`x/y@…`) and no computer accounts (`pc$`). It rejects NTLM.
3. The user in the request MUST correspond to the principal. The server then checks both documents as for `PUT` and records the **attestation** `{user, sign_pub, principal, at}`.
4. Only an admin can still approve, because only an admin signs the roster. `cljpass auto-approve` fetches the attestations (`GET /v1/kerberos`, admins only) and takes every open request whose `sign_pub` exactly matches the attestation into a new roster version. Disabled users (`disabled`) are not automatically reactivated.

With `--require-kerberos`, the server no longer accepts `PUT requests/…`. Then nobody can submit a request without a valid ticket.

**Trust:** Whoever runs `auto-approve` trusts the server's attestation and thus the AD. A compromised server or domain admin could inject a request in a user's name. That does not give them earlier passwords, but it does give them everything shared with this user or their groups afterwards. Anyone who does not want that approves without `auto-approve`: `cljpass requests` then shows the Kerberos attestation only as a hint.

## 9. Transport and synchronization

A transport needs exactly four operations:

| Operation | Semantics |
|---|---|
| `get(path)` | bytes or "not present" |
| `list(prefix)` | names of the direct children |
| `create(path, bytes)` | **create only**. If the object exists, the result is `conflict` |
| `put(path, bytes)` | overwrite, only for `requests/` and `escrow/` |

The reference implementation uses **SQLite** on both sides: on the server as the database, in the client as the cache. The table `objects(seq, path UNIQUE, body, created_at)` maps `create` to `INSERT` (conflict on an existing path) and `put` to `REPLACE`. `seq` increases with every write and enables incremental sync.

**HTTP API of the server** (TLS via a reverse proxy):

| Request | Purpose | Authentication |
|---|---|---|
| `GET /v1/health` | liveness | none |
| `GET /v1/org` | `org.json`. The client checks the pin | none |
| `GET /v1/changes?since=N&limit=M` | objects with `seq > N`: `{"objects":[{"seq","path","body"}],"more":bool}` | active user or admin |
| `PUT /v1/objects/<path>` | `create`, for `requests/` and `escrow/` `put`. Response 201, 409 on conflict, 422 for an invalid object | see below |
| `POST /v1/enroll` | request + escrow with Kerberos (§8.1). 201, 401 with `WWW-Authenticate: Negotiate`, 403 for another user | Kerberos |
| `GET /v1/kerberos` | Kerberos attestations `{"attestations":[{"user","sign-pub","principal","at"}]}` | admin |
| `GET /v1/audit?since=N&limit=M` | audit log (§9.2) `{"entries":[…],"more":bool}` | admin |

**Authentication without a DC:** Every request carries
`Authorization: CljPass u=<user>,t=<unix-ms>,n=<nonce>,s=<sig>` with
`sig = Ed25519(sign_priv, "cljpass-req-v1\n" METHOD "\n" path+query "\n" t "\n" n "\n" hex(sha256(body)))`.
- The server accepts ±5 minutes of clock skew and each nonce only once.
- Valid keys are those of the active users in the newest roster and of the admins from `org.json`.
- For `requests/<u>`, the key from the request itself applies. For `escrow/<u>`, the key of the request or of the active user applies.
- The signer of the object MUST be the authenticated user.
- `org.json` may be created only once, and only with the server's init token (`X-Init-Token`).

**Validation in the server:** Before storing, the server checks every object according to §4–§8. It needs only public keys for this; it trusts nobody and nobody has to trust it.
- Roster versions must be consecutive without gaps.
- Entry versions must carry the number `max + 1` and satisfy §6.1.
- Group documents must satisfy G1/G2.
- Writes are serialized.

Authentication only protects against misuse of the server. Confidentiality and integrity do not depend on it.

**Sync procedure in the client:**
1. Check `org.json` against the pin, then load and verify the roster (§5).
2. Group maintenance (§7).
3. Load and verify entries (§6.1), update the local cache and store the anti-rollback state.
4. Apply queued changes (see below).

**Offline:**
- Reading works from the local cache. These are the same objects, unchanged and thus still signed and encrypted.
- Changes go into the cache immediately, so that they are visible to the user, and into a local queue (`outbox`).
- Before every write, the client fetches the newest state (roster, head versions) if possible.
- When applying, the following is checked:
  - If the head is still the base version, the write happens.
  - Otherwise there is a **conflict**, and the user chooses "keep mine" (new version on top of the new head) or "discard". Nothing is lost silently.
  - If the user has lost the permission in the meantime, the server rejects the write (422). The client reports this. The draft stays encrypted locally in the queue until the user discards it.
  - If fetching returns someone else's version with the same path as one of the user's own that has not been uploaded yet: the other version wins, and the user's own is marked as a conflict.

### 9.2 Audit log of the server

The server logs security-relevant events in the `audit` table of its database. In addition, it writes every event as a JSON line with the prefix `AUDIT ` to stdout, e.g. for journald or syslog.

| Event | When |
|---|---|
| `server.start` | start, with Kerberos realm and options |
| `vault.init`, `vault.init-denied`, `vault.init-rejected` | creating the vault |
| `object.create`, `object.put` | accepted object (path, user) |
| `object.rejected`, `object.conflict`, `object.error` | rejected object, with reason |
| `enroll.request` | request via `PUT` (with fingerprint) |
| `enroll.kerberos` | request with Kerberos (principal, fingerprint) |
| `enroll.denied` | request rejected (another user, Kerberos required) |
| `kerberos.failed` | ticket invalid, NTLM, foreign realm |
| `auth.failed`, `auth.forbidden` | invalid signature, writing in someone else's name |
| `kerberos.list`, `audit.read` | admin reads attestations or the log |

Fetching (`/v1/changes`) is not logged, because clients poll it regularly.

Entry: `{seq, at, event, user?, addr?, path?, detail?, prev, hash}` with `hash = hex(SHA-256(canonical JSON of all other fields))` and `prev` = `hash` of the predecessor (64 × `0` for the first entry). `addr` is the client address; with `--trust-proxy`, the last value from `X-Forwarded-For`.
`cljpass audit` verifies the chain. This reveals if individual entries in the database were changed or deleted. Whoever controls the whole server can recompute the chain. Only the copy via stdout on another system helps against that.

### 9.1 Example: read permission on the iPhone, user changes the password

1. **Normal app:** The field is read-only and the edit button is missing, just as in Passbolt. The client knows the effective permission from the ACL.
2. **Manipulated app or direct file access:** The client itself would already reject the version (E6). If it is written anyway:
   - All other clients discard it (E3/E6) and show W1: "invalid change by bob discarded".
   - The head remains the last valid version. The real password is unchanged, and nobody gets to see the wrong value.
   - The server already rejects the version on `PUT` (422).
3. The user may create a **copy for themselves** ("duplicate" is allowed with read permission). That is then their own entry. The shared entry remains untouched.

## 10. Recovery

- `recovery_pub` from `org.json` opens every escrow. The private recovery key SHOULD be distributed to M-of-N people via Shamir secret sharing (v2) and stored offline.
- An admin alone has no access. The recovery holders together have access to everything. This MUST be governed accordingly in the organization.

## 11. Memory (modeled on KeePass)

- Private keys and payloads exist in the process only encrypted with a process-specific random key (AES-GCM). The plaintext exists only during an operation and is overwritten afterwards.
- Automatic lock after idle time. All secrets are discarded, and unlocking goes through DPAPI or Face ID again.
- Clipboard:
  - Cleared after 12 s, but only if it still contains our value.
  - On Windows with the formats `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`=0 and `CanUploadToCloudClipboard`=0.
- Limit: Displayed or copied values become strings of the runtime, which only the garbage collector removes. This is the same as with KeePass on .NET and is documented, not concealed.

## 12. Versioning

- The field `v` in the envelope is 1.
- New optional fields in the payload do not increase `v`.
- New mandatory rules or primitives result in `v` = 2. A client MUST reject unknown `v` and must not ignore them.

## 13. Local mode (without a server)

The server is optional. A device works either in **server mode** (§4–§9) or in **local mode** with a KeePass file. You can switch in both directions at any time.

**File.** The local vault is an ordinary KDBX file that KeePass and KeePassXC can also open. It is protected with a master password and/or key file. In local mode there is no identity, no DPAPI, no server and no sharing.
- An entry ID is the KeePass UUID of the entry (16 bytes as UUID text). This keeps it stable across saves. A new entry gets a random ID, and its UUID is derived from it.
- The file is saved after every change, atomically via a temporary file. §6.3 applies: unchanged entries, Meta, group tree, attachments, plugin data and unknown elements are preserved exactly. A changed entry puts its old state into the history. The key derivation of the file (Argon2d/id, AES-KDF including parameters) is preserved. KDBX 4 with AES-256 is always written.
- Deleting removes the entry and records it in `DeletedObjects`, like KeePass without a recycle bin.
- If another program has changed the file since it was loaded (SHA-256 of the content), the client MUST reload it before the next change.
- In memory, §11 applies: the master key and entries exist only in encrypted form. Locking discards both.

**Synchronizing with another file** (as in KeePass). Entries are matched by their UUID:
- In both files: the newer `LastModificationTime` wins. The other state and its history go into the history, as far as they are not already there.
- Only in one file: the entry is taken over. Exception: the other file has it in `DeletedObjects` with a `DeletionTime` ≥ its last modification. Then it is deleted.
- `DeletedObjects` of both files are merged. The result is written to both files, each with its own key.

**Server → file** (disconnect). All readable entries are exported with origin markers:
- per entry, `CustomData` `cljpass/source` = `{"id":"<vault ID>","version":n,"hash":"<SHA-256 over fields and folder>"}`
- in `Meta/CustomData`, `cljpass/database` = ID of the database record (§6.3)

The identity and cache remain on the device, the user remains in the roster. The configuration remembers the server as `link`.

**File → server** (connect).
1. Enrollment as in §8. Anyone already approved is ready immediately.
2. Until approval, the user continues working with the file.
3. Then the file is reconciled with the vault. The target is the entry with the marker `id`, otherwise the one with the same KeePass UUID:

| Case | Result |
|---|---|
| no target | new entry, owner: me |
| fields equal, or locally unchanged (`hash` matches) | nothing, the vault stays as is |
| only changed locally (`version` = head version) and permission `update` | new version in the vault |
| both changed, without marker or without permission | copy "… (local change)", nothing is lost |
| deleted locally (`DeletedObjects`), permission `owner`, unchanged in the vault since the deletion | deleted in the vault |

The reconciliation is idempotent: switching back and forth repeatedly without changes creates no duplicates. The file remains as a backup.

**Policy.** With `{:standalone false}` in `org.edn`, IT disables local mode.

### 13.1 Offline copy of a file on a network share

If the file is on a share (NAS, Windows server), the client works with a local copy in `<home>/offline/` and reconciles it with the file on the share. This way reading and editing work even when the share is unreachable (NAS off, no VPN, not mounted).
- **On/off:** per file in `config.edn` as `:offline-copies {"<path>" true|false}`. Without an entry, the copy is on if the file is on a network share (Linux: mount type according to `/proc/mounts`, e.g. `cifs`, `nfs`, `fuse.sshfs`; Windows: UNC path `\\server\share`).
- **State:** Next to the copy lies `<copy>.edn` with `{:file F :remote S1 :local S2}`, the SHA-256 values of the share file and the copy at the last successful reconciliation. Pending changes follow from these, so a crash between copy and share loses nothing.
- **Reconciliation** on opening, before and after every change and on synchronizing (F5, every 60 s in the background):

| Copy changed | Share changed | Result |
|---|---|---|
| no | no | nothing |
| no | yes | the copy takes over the file unchanged (decrypt first, then write) |
| yes | no | the copy is written to the share |
| yes | yes | merge as in *Synchronizing with another file* (above), the result goes into both |

- Writes are atomic via a temporary file, and only if the file still has the state just read. Otherwise reconciliation starts over.
- Every access to the share runs with a time limit (5 s), so that a hanging mount does not block the user interface. If the share is unreachable, changes retry it at most every 30 s.
- A missing file on the share counts as unreachable. It is never recreated, and no folders are created.
- Changing the master key and switching off the copy only work when the share is reachable and reconciled. If the master key of the share file no longer matches (changed elsewhere), the copy remains unchanged and the error is shown.

## Appendix A – Implementation on the platforms

| Building block | JVM (JCA) | iOS (Swift, CryptoKit) | Web (WebCrypto) |
|---|---|---|---|
| Ed25519 | `Signature "Ed25519"` (raw ↔ X.509 via fixed 12-byte prefix) | `Curve25519.Signing` | `Ed25519` (Chrome 137+, Firefox 129+, Safari 17+) |
| X25519 | `KeyAgreement "X25519"` | `Curve25519.KeyAgreement` | `X25519` |
| HKDF | own HMAC implementation | `HKDF<SHA256>` | `HKDF` |
| AES-GCM | `AES/GCM/NoPadding` | `AES.GCM` | `AES-GCM` |
| local key protection | DPAPI via PowerShell | Keychain / Secure Enclave | – (web only via the local service, see Appendix B) |

## Appendix B – User interfaces

**Desktop (v1).** The client has a native user interface (SWT) laid out like KeePass. It runs in the same process as cryptography and cache. There is no local network service and no browser.

**Web (basis for a Firefox add-on).** The former local web app remains in the code (`cljpass.web`, `resources/ui`):
- It runs on `127.0.0.1` with a random port and an access token per session.
- `Host` and `Origin` are checked (protection against DNS rebinding and CSRF).
- The cryptography stays in the local process.

A Firefox add-on can build on this: the extension displays, `cljpass` remains the engine, connected via Native Messaging or the local interface.

A **centrally served** web app with cryptography in the browser would be more convenient. But then the server could serve manipulated JavaScript. Passbolt uses a browser extension for exactly this reason.

## Appendix C – Reusing the Passbolt iOS client (later)

`passbolt_ios` is licensed under AGPL-3.0 and written in Swift. The reuse has only been planned, not checked against the code.

- **Reusable:** UI modules (resource list, details, share dialog, folders), AutoFill extension, biometrics/Keychain handling, offline cache structure.
- **To be replaced:** the OpenPGP layer (gopenpgp) with CryptoKit according to §2, the REST API layer with the transport according to §9, the setup and account transfer with §8.
- **License:** A derived client MUST remain AGPL-3.0, and the source code must be accessible to users. The "Passbolt" trademark must not be used.
