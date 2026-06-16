# Code Signing — Bootstrap & Troubleshooting

`arcbox-daemon` uses restricted macOS entitlements
(`com.apple.security.virtualization`, `com.apple.vm.networking`) that require a
**Developer ID** signature. Ad-hoc signing (`-s -`) does **not** work — the
kernel kills the process on launch.

This doc is the deep-dive companion to the
[Code Signing section in `CONTRIBUTING.md`](../CONTRIBUTING.md#code-signing).
Start there for the basic setup; come here when signing fails or behaves oddly.

- [Bootstrap (first-time setup)](#bootstrap-first-time-setup)
- [Diagnostic flow](#diagnostic-flow)
- [Issue: "unable to build chain to self-signed root" / `errSecInternalComponent`](#issue-unable-to-build-chain-to-self-signed-root--errsecinternalcomponent)
- [Issue: keychain asks for a password on every sign](#issue-keychain-asks-for-a-password-on-every-sign)
- [Issue: the signing identity is duplicated across keychains](#issue-the-signing-identity-is-duplicated-across-keychains)
- [Troubleshooting quick reference](#troubleshooting-quick-reference)

---

## Bootstrap (first-time setup)

You need three things (ask a team lead for the first two — they are distributed
internally and **must not** be committed):

| Item | What | How |
|------|------|-----|
| Developer ID certificate | `Developer ID Application: ArcBox, Inc. (422ACSY6Y5)` | Import the `.p12` into the **login** keychain |
| Provisioning profile | `ArcBox_Daemon_DeveloperID.provisionprofile` | Double-click to install |
| Entitlements | `bundle/arcbox.entitlements` | Already in the repo |

Import the `.p12` (this brings in the leaf certificate **and** its private key):

```bash
# Either double-click the .p12 in Finder, or:
security import ArcBox_DeveloperID.p12 -k ~/Library/Keychains/login.keychain-db
```

Then sign and verify:

```bash
make sign-daemon                         # auto-detects the identity from keychain
codesign --verify --strict --verbose=2 target/debug/arcbox-daemon
```

A correct setup verifies with the **full chain to a self-signed root**:

```
Authority=Developer ID Application: ArcBox, Inc. (422ACSY6Y5)   # leaf
Authority=Developer ID Certification Authority                 # intermediate
Authority=Apple Root CA                                         # self-signed root ✓
TeamIdentifier=422ACSY6Y5
```

> [!TIP]
> Apple's intermediate (`Developer ID Certification Authority`) and root
> (`Apple Root CA`) ship with macOS. You normally do **not** need to import them
> manually. If a chain error tempts you to, read the diagnostic flow first — a
> missing intermediate is rarely the real cause.

---

## Diagnostic flow

Run these read-only checks before changing anything. They tell you *which* of
the three layers (leaf / intermediate / root) is actually broken, so you don't
fix the wrong thing.

```bash
# 1. Is the leaf present, with its private key, and valid?
security find-identity -v -p codesigning | grep ArcBox

# 2. What does the leaf chain to? (note the issuer CN)
security find-certificate -c "Developer ID Application: ArcBox" -p \
  | openssl x509 -noout -issuer -subject -dates

# 3. Is the intermediate present and unexpired?
security find-certificate -a -c "Developer ID Certification Authority" -p \
  | openssl x509 -noout -subject -dates    # repeat per cert if multiple

# 4. Is the self-signed root present?
security find-certificate -c "Apple Root CA" >/dev/null 2>&1 \
  && echo "Apple Root CA: present" || echo "Apple Root CA: MISSING"

# 5. Does the chain evaluate under the code-signing policy?
security find-certificate -c "Developer ID Application: ArcBox" -p > /tmp/leaf.pem
security verify-cert -c /tmp/leaf.pem -p codeSign; rm -f /tmp/leaf.pem

# 6. THE KEY CHECK — are there manual trust overrides? (both domains)
security dump-trust-settings        # user domain
security dump-trust-settings -d     # admin domain (most overrides land here)

# 7. Which keychains hold the usable identity (cert + private key)?
#    More than one line here means a duplicate — see the dedicated issue below.
security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db | grep ArcBox
security find-identity -v -p codesigning /Library/Keychains/System.keychain   | grep ArcBox
```

> [!WARNING]
> `security verify-cert` can report **success** while `codesign` still **fails**.
> `verify-cert` honors manual trust overrides; `codesign` ignores them and
> insists on building to the real Apple Root CA. If step 5 passes but signing
> fails, the culprit is almost always step 6.

---

## Issue: "unable to build chain to self-signed root" / `errSecInternalComponent`

Symptom — `make sign-daemon` prints:

```
Warning: unable to build chain to self-signed root for signer "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)"
target/.../arcbox-daemon: errSecInternalComponent
```

The first line (the *Warning*) is the real diagnosis; `errSecInternalComponent`
is just the generic "chain incomplete, signing aborted" fallout.

### Most common real cause: a manual "Always Trust" override on the leaf

If someone opened Keychain Access and set the **leaf** certificate
(`Developer ID Application: ArcBox`) to **"Always Trust"**, it leaves a trust
setting of type `kSecTrustSettingsResultTrustAsRoot`. That tells the evaluator
"treat this leaf as a trusted root, stop here" — so the chain is truncated at
the leaf and never reaches `Apple Root CA`. `codesign` rejects that and emits
the chain error above.

Confirm (look for `Result Type: kSecTrustSettingsResultTrustAsRoot` on the
leaf):

```bash
security dump-trust-settings -d     # check admin domain
security dump-trust-settings        # and user domain
```

**Fix** — remove the override. It usually lives in the **admin** domain (`-d`),
which needs `sudo` and an interactive terminal (run in **Terminal.app**, not via
a non-interactive shell):

```bash
security find-certificate -c "Developer ID Application: ArcBox" -p > /tmp/leaf.pem
sudo security remove-trusted-cert -d /tmp/leaf.pem      # admin domain
# If it's in the user domain instead, drop sudo and -d:
#   security remove-trusted-cert /tmp/leaf.pem
rm -f /tmp/leaf.pem
```

GUI equivalent: Keychain Access → double-click the cert → **Trust** → set
*"When using this certificate"* back to **"Use System Defaults"**.

Then re-sign — the warning is gone and the chain reaches `Apple Root CA`:

```bash
make sign-daemon
codesign -dvv target/debug/arcbox-daemon | grep Authority
```

> [!IMPORTANT]
> **Never** set "Always Trust" on your own signing certificate. It does not help
> signing — it *breaks* it. Keep signing certs on "Use System Defaults".

### Other causes to rule out

- **Private key missing** — only the cert was imported, not the key.
  `security find-identity -v -p codesigning` won't list it. Re-export the `.p12`
  with both cert **and** private key selected, and re-import.
- **Genuinely missing intermediate/root** — rare on a normal macOS install.
  Confirm with diagnostic steps 3–4. Only then import from Apple:
  - <https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer>
  - <https://www.apple.com/certificateauthority/AppleIncRootCertificate.cer>

---

## Issue: keychain asks for a password on every sign

Symptom — every `make sign-daemon` pops a dialog:
*"codesign wants to sign using key … in your keychain"* with **Allow** /
**Always Allow**. Clicking **Allow** (not **Always Allow**) means it asks again
next time.

**Cause** — the private key's access control list (partition list) does not
include `codesign`. This is the default state after importing a `.p12` from the
command line, so the keychain prompts for confirmation on each use.

**Fix A — one command, permanent (recommended).** Adds `codesign` to the key's
partition list. Replace `<login-password>` with your macOS login password (the
login-keychain password). Run in **Terminal.app**:

```bash
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s -k "<login-password>" \
  ~/Library/Keychains/login.keychain-db
```

> [!NOTE]
> The password appears in shell history. To avoid that, prompt for it instead:
> `read -rs PW && security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$PW" ~/Library/Keychains/login.keychain-db; unset PW`

**Fix B — GUI.** Keychain Access → **login** keychain → category **Keys** →
expand the private key under `Developer ID Application: ArcBox` → right-click →
**Get Info** → **Access Control** → either choose *"Allow all applications to
access this item"*, or keep *"Confirm before allowing access"* and **+** add
`/usr/bin/codesign` to the list. Save (one password prompt).

After either fix, `make sign-daemon` signs without prompting.

> [!IMPORTANT]
> If Fix A and Fix B both appear to work yet the prompt persists, the key
> `codesign` actually uses is in a **different keychain** than the one you
> patched — see the next issue.

---

## Issue: the signing identity is duplicated across keychains

Symptom — the per-sign password prompt **survives** both fixes above, *and/or*
`codesign` behaves as if your `set-key-partition-list` / Access Control changes
had no effect.

**Cause** — the same identity (cert + private key) exists in **more than one
keychain**, typically both `login.keychain-db` and the **System keychain**
(`/Library/Keychains/System.keychain`). This happens when the `.p12` was
imported into the System keychain at some point (e.g. `sudo security import …
-k /Library/Keychains/System.keychain`).

Two consequences:

1. **Search order picks the wrong copy.** `security list-keychains` puts
   `System.keychain` **before** `login.keychain-db`, so when an identity exists
   in both, `codesign` resolves to the System-keychain copy.
2. **The System-keychain copy prompts on every use.** A private key in the
   System keychain requires per-use admin authorization for a normal user (its
   keychain password is the machine-generated one in `/var/db/SystemKey`, not
   your login password). So fixes applied to the **login** copy never take
   effect — `codesign` isn't using that copy.

Confirm (two lines of output → the identity is in both keychains):

```bash
security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db | grep ArcBox
security find-identity -v -p codesigning /Library/Keychains/System.keychain   | grep ArcBox
```

**Fix** — signing identities belong in the **login** keychain. Delete the
duplicate from the System keychain so `codesign` falls back to the login copy.
Run in **Terminal.app** (needs `sudo`); substitute the SHA-1 from
`find-identity` if yours differs:

```bash
# 1. Remove the ArcBox identity (cert + private key) from the System keychain
sudo security delete-identity \
  -Z 34B370D02E5D7D81DFD7739FA0BC0C25AE948ACC \
  /Library/Keychains/System.keychain

# 2. Confirm: login still has it, System is now empty
security find-identity -v -p codesigning ~/Library/Keychains/login.keychain-db | grep ArcBox
security find-identity -v -p codesigning /Library/Keychains/System.keychain   | grep ArcBox   # expect: empty

# 3. Re-apply the partition-list fix to the login copy (now the only one codesign can use)
security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
  -k "<login-password>" ~/Library/Keychains/login.keychain-db
```

`make sign-daemon` should now sign without any prompt.

> [!NOTE]
> Step 1 only touches the System-keychain copy; the login copy (confirmed to
> carry the private key and able to sign) is untouched, so there is no risk of
> losing the ability to sign. If unsure, run steps 1–2 first and verify before
> re-signing.

---

## Troubleshooting quick reference

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `unable to build chain to self-signed root` + `errSecInternalComponent` | Manual "Always Trust" (`TrustAsRoot`) override on the leaf cert | `sudo security remove-trusted-cert -d <leaf.pem>` ([details](#issue-unable-to-build-chain-to-self-signed-root--errsecinternalcomponent)) |
| `errSecInternalComponent`, no leaf in `find-identity` | Private key not imported (cert only) | Re-export `.p12` with the private key, re-import |
| `verify-cert` passes but `codesign` fails | Trust override masks the broken chain | Check `dump-trust-settings -d`, remove the override |
| Password dialog on **every** sign | `codesign` not in the key's partition list | `security set-key-partition-list …` ([details](#issue-keychain-asks-for-a-password-on-every-sign)) |
| Password prompt persists after partition-list / Access-Control fixes | Identity duplicated in the System keychain; `codesign` uses that copy | `sudo security delete-identity -Z <SHA-1> /Library/Keychains/System.keychain` ([details](#issue-the-signing-identity-is-duplicated-across-keychains)) |
| `codesign: ambiguous identity` | Duplicate certs with the same name | `security delete-identity -Z <SHA-1>` to prune duplicates |
| `zsh: killed` on launch (exit 137) | Missing provisioning profile, or `--options runtime` omitted | Install the `.provisionprofile`; always sign with `--options runtime` |

See also: [`CONTRIBUTING.md` § Code Signing](../CONTRIBUTING.md#code-signing),
[`docs/daemon-lifecycle.md`](daemon-lifecycle.md).
