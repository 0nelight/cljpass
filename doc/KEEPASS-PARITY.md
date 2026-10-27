# Feature parity with KeePass 2.x

Goal: anyone coming from KeePass (or KeePassXC) finds everything they need day to day in cljpass, and can keep opening the same file in KeePass. This document is the strategy for that: principles, a feature-by-feature comparison, and the order in which the gaps are closed.

## Principles

1. **The file is the truth.** Every feature maps losslessly onto KDBX, the way KeePass stores it: tags in `<Tags>`, attachments as `<Binary>`, history in `<History>`, settings in `<Meta>`. A feature only counts as done once a test reads the written file the way KeePass reads it.
2. **One implementation for both modes.** The logic lives in `keepass.clj` (KDBX mapping) and `service.clj`. The payload in the vault has the same shape as in local mode, so tags, attachments, TOTP and history also work on the server and end up in the file on export. Exceptions are justified explicitly, e.g. that history cannot be deleted in the vault because it is immutable.
3. **Layers from the bottom up:** core with tests → service (both modes) → UI/CLI → UI self-test.
4. **Order by everyday value divided by effort.** Platform-specific and rarely used features (Auto-Type, triggers) come last.
5. **Security boundaries stay:** the UI only gets what it displays. For TOTP that is the current code, not the secret; for the password check it is only the IDs of the affected entries.

Legend: ✅ available · 🆕 new in stage 1 · 🆕² new in stage 2 · ◐ partial · ⏳ planned (stage) · ✗ deliberately not

## Comparison

### Database and file

| KeePass | cljpass | Notes |
|---|---|---|
| Read KDBX 3.1/4.x, write KDBX 4 | ✅ | AES, ChaCha20, Twofish; AES-KDF, Argon2d/id |
| Master password, key file (XML v1/v2, hex, arbitrary) | ✅ | |
| Windows user account as key component | ⏳ 3 | In server mode DPAPI already protects the identity |
| Change master key | 🆕 | File > Change Master Key, sets `MasterKeyChanged` |
| Database settings | ◐🆕 | Name, description, default user name, history length, recycle bin on/off 🆕². ⏳ 2: color, KDF parameters, compression |
| Save as / copy | ✅ | |
| Synchronize with file | ✅ | The newer change wins, deletions are applied |
| Detect external changes | ✅ | Reload before saving |
| Recently opened files | 🆕² | File > Open Recent (10, newest first) |
| Several databases at once (tabs) | ✅ | File > Open in New Tab; locking applies to all tabs |
| AutoOpen (KeeAutoExec plugin, KeePassXC) | ✅ | Group `AutoOpen` with Enabled, Priority, IfDevice, Skip…, Focus; without a key or with a wrong one, the unlock dialog asks. Tests: `test/cljpass/autoopen_test.clj` |

### Entries

| KeePass | cljpass | Notes |
|---|---|---|
| Title, user name, password, URL, notes | ✅ | |
| Custom fields (protected/unprotected) | ✅ | |
| Expiry date | 🆕² | With time of day (entered in local time, stored as UTC in the file like KeePass). Older data with a plain date keep the time from the file; syncing with the server also detects time-only changes, old origin markers still apply |
| Tags | 🆕 | `<Tags>`, separated by `;` or `,` |
| Attachments | 🆕 | Attach, save as, replace, remove. Up to 2 MB per file in the vault |
| Show history | ✅ | |
| History: view, restore, delete a version | 🆕 | In the vault: restoring creates a new version; there is no deleting |
| History length (`HistoryMaxItems`) | 🆕 | ⏳ 2: `HistoryMaxSize` |
| TOTP | 🆕 | KeePass `TimeOtp-*`, KeePassXC `otp`, TrayTOTP; Ctrl+T copies. ⏳ 3: HOTP, QR code |
| Show icons (standard and custom) | ✅ | |
| Choose icon and colors | 🆕² | Button next to the title (69 standard icons), foreground/background color under *Properties*, colors in the list. A standard icon replaces a custom one; adding custom icons ⏳ 3 |
| Duplicate | ✅ | ⏳ 2: options (references instead of copies, include history) |
| Multiple selection, move by drag and drop | 🆕² | Drag entries (also several) onto a group, groups onto groups; Entry > Move to Group, Edit Tags, Delete for the whole selection, Ctrl+A. In the vault only where you have the right |
| Field references `{REF:…}`, placeholders `{USERNAME}` … | ⏳ 3 | |
| URL override, entry templates | ⏳ 3 | Both are preserved in the file |

### Groups

| KeePass | cljpass | Notes |
|---|---|---|
| Group tree | ✅🆕² | Built from the folder paths, locally also empty groups |
| Create, rename, move, delete groups | 🆕² | *Group* menu and context menu in the tree. Locally on the file's group tree (UUID is kept). Server: rename/move changes the folder of every entry you may change; empty groups and deleting only locally |
| Recycle bin | 🆕² | Like KeePass: `RecycleBinUUID`, icon 43, not searched; deleting from the recycle bin is permanent (`DeletedObjects`), empty recycle bin. When switching to the server the recycle bin counts as deleted |
| Group icons | 🆕² | Group > Change Icon (local) |

### Search and filter

| KeePass | cljpass | Notes |
|---|---|---|
| Quick search | ✅🆕 | Now also tags, unprotected custom fields, several words (all must match) |
| Case sensitivity, regular expressions | 🆕 | Search menu |
| Expired entries | ✅ | |
| Entries expiring soon | 🆕 | 7 days |
| Entries by tag | 🆕 | Search > Entries with Tag |
| Duplicate passwords, weak passwords | 🆕 | Only IDs leave the service |
| Search dialog with field selection, search in passwords | ⏳ 2 | |
| Similar passwords | ⏳ 3 | |

### Passwords and clipboard

| KeePass | cljpass | Notes |
|---|---|---|
| Generator with character sets | ✅ | |
| Generator: patterns, custom characters, profiles | 🆕² | Patterns in KeePass syntax (`u l d h H s a A v c …`, `\X`, `{n}`, `[…^…]`, permute), custom and excluded characters, each character at most once. Profiles: built-in ones like KeePass (hex key, MAC address, PIN) and custom ones (local settings) |
| Quality bar | 🆕² | Pattern detection like KeePass: common passwords and words (German/English, leetspeak, capitalization, reversed), repetitions, sequences, keyboard sequences, years; cheapest decomposition by dynamic programming |
| Clipboard with clearing and history exclusion | ✅ | |
| Auto-Type (global and per entry) | ⏳ 3 | Platform-specific, Windows first; settings are preserved in the file |

### Import, export, print

| KeePass | cljpass | Notes |
|---|---|---|
| Import/export KDBX | ✅ | Lossless |
| CSV import/export (KeePass, KeePassXC) | 🆕² | Import detects columns by name (KeePass 1.x/2.x, KeePassXC, German names), separators `,` `;` tab; unknown columns become custom fields. Export with KeePassXC's columns, TOTP as an otpauth URI |
| KeePass XML import/export | 🆕² | KeePass XML (2.x) lossless: `ProtectInMemory`, attachments in `Meta/Binaries` |
| Print / HTML export | 🆕² | File > Print (Ctrl+P): HTML per group, passwords only on request, opens in the browser |
| Export via XSL stylesheet | 🆕² | Like KeePass "Transform using XSL Stylesheet" (e.g. `KDBX_DetailsLight_HTML.xsl`). Saxon-HE, also in the native binary: no Java extensions, files only from the stylesheet's folder (`xsl:include` of `KDBX_Common.xsl`), no other paths/URLs |
| Import from other managers (Bitwarden, 1Password, …) | ◐🆕² | CSV from Bitwarden, Chrome, Firefox is detected. ⏳ 3: native formats (JSON, 1PUX) |

### User interface and security

| KeePass | cljpass | Notes |
|---|---|---|
| Menus, toolbar, keyboard shortcuts like KeePass | ✅ | New: Ctrl+T for TOTP, Ctrl+A select all, *Group* menu |
| URLs as links | 🆕² | Like KeePass: in the entry view the URL and addresses in the notes are links (`UIUtil.RtfLinkifyUrls`), a click opens the browser. In the list a double click on the *URL* column opens the address (`OnPwListMouseDoubleClick`), otherwise it opens the entry as before. Only http(s) addresses are opened |
| Choose columns, reveal passwords in the list | 🆕² | View > Columns (also Group, Tags, Expires, Modified, Attachments), View > Show Passwords in List; remembered in the local settings |
| Minimize to the notification area | ⏳ 3 | |
| Memory protection, lock after idle | ✅🆕² | Tools > Options: lock time (0 = never) and time until the clipboard is cleared |
| Enter master key on a secure desktop | ⏳ 3 | Windows only |
| Triggers | ⏳ 3 | Not before Auto-Type |
| Plugins | ✗ | .NET-specific and a large attack surface; plugin data in the file is preserved. Widely used plugins are rebuilt when needed (AutoOpen) |
| Multiple languages | ✅ | English and German, View > Language (automatic follows the system) |

## Stages

### Stage 1: done

The features most often missed day to day that need no new dependencies:

- TOTP in all common formats (`cljpass.otp`), including a setup dialog and Ctrl+T
- Tags: field in the entry, display, search, filter by tag
- Attachments: in the entry dialog under *Advanced*, in both modes
- History: view, restore and (locally) delete an older version; limit like KeePass
- Search across tags and custom fields, with case sensitivity and regular expressions
- Filters: expiring soon, duplicate and weak passwords
- File > Change Master Key, File > Database Settings, default user name for new entries

Tests: `test/cljpass/parity_test.clj` (RFC 6238 test vectors, all TOTP formats, round trip through the file, server mode with export).

Stage 2 is implemented item by item; tests in `test/cljpass/groups_test.clj` (group tree, recycle bin, bulk operations, icons and colors, checked via the written file; server mode), `test/cljpass/exchange_test.clj` (CSV, KeePass XML, HTML, XSL stylesheets including attacks through the stylesheet), `test/cljpass/generator_test.clj` (patterns, character sets, profiles, quality) and `test/cljpass/settings_test.clj` (expiry with time of day including the server round trip, recently opened files, lock time).

### Stage 2: structure and data exchange (done)

1. ✅ Group management on the group tree in `skeleton` (create, rename, move, delete, show empty groups) and recycle bin with `RecycleBinUUID`. In server mode the folder stays a field per entry; renaming changes every entry you may change.
2. ✅ Multiple selection and drag and drop in the list (move, delete, set tags).
3. ✅ Icon and color choice for entries and groups.
4. ✅ CSV and KeePass XML import/export, print/HTML, export via XSL stylesheet.
5. ✅ Generator with patterns, custom characters and profiles; quality estimate with pattern detection.
6. ✅ Expiry date with time of day, column selection, configurable lock time, recently opened files.

### Stage 3: platform and automation

1. Auto-Type (Windows first): global hotkey, window matching, default sequence, placeholders and field references.
2. ✅ Several databases at once (tabs) and AutoOpen. Open: Windows user account as key component, secure desktop.
3. HOTP (writing the counter back), show QR code, similar passwords.
4. Import from other password managers, triggers.

Each stage ends like stage 1: tests via the written file, service tests in both modes, UI self-test (`gui --smoke`) and this table updated.
