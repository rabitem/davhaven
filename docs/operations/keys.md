# The key ring

Davhaven derives every secret it needs at runtime from a small set of long random keys that the deployment supplies as
files. This page says what the keys protect, the exact format of a key file, and how to add, rotate and retire a key
(the rules are R6 of [`ENGINEERING_RULES.md`](../ENGINEERING_RULES.md); the decisions behind the formats are in
[ADR-0007](../adr/0007-derived-rsvp-tokens.md) and [ADR-0012](../adr/0012-authentication-failures-credential-format-and-fenced-idempotency.md)).

## What the keys protect

Nothing signs or encrypts with a configured key directly. For every purpose the server derives a subkey with HKDF-SHA256
from the key and a label that names the purpose, so a value made for one purpose never verifies for another and the key of the
sealer is unrelated to every MAC key.

| Purpose | What it protects | Lifetime of the values |
| --- | --- | --- |
| Credential pepper | The keyed hashes of app passwords, API tokens, feed tokens and RSVP tokens (HMAC-SHA256); every hash records the id of the key that made it | Until the credential is revoked |
| RSVP | The derivation of the RSVP link tokens of invitation mails ([ADR-0007](../adr/0007-derived-rsvp-tokens.md)) | Until the link expires (the end of the event plus 7 days, at most a year) |
| CSRF | The CSRF tokens of the RSVP page | 1 hour |
| Cursor | The signature of pagination cursors of the management API | Short |
| Cache key | The key of the verified-credential cache | 5 minutes |
| Sealer | Secrets that are stored and used again: webhook signing secrets (XChaCha20-Poly1305; the key id is part of every sealed value) | Until the secret is rotated or the subscription deleted |

Two consequences matter operationally. A **lost key** makes everything under it unusable: the credentials hashed with it no
longer verify (every client has to log in with a new app password) and the secrets sealed with it cannot be opened (webhook
secrets have to be rotated). And **whoever holds a key and a copy of the database** can recompute RSVP links and unseal webhook
secrets: keep the key files where the database credentials live, separate from the database backups, and never in the image or the
repository.

## The key file

Configure the ring in the TOML file or the environment:

```toml
[[security.keys]]
id = "2027-01"
secret_file = "/run/secrets/davhaven-key-2027-01"

[[security.keys]]
id = "2026-07"
secret_file = "/run/secrets/davhaven-key-2026-07"

[security]
active_key_id = "2027-01"        # the key that signs, hashes and seals new data; the first key when absent
```

or `DAVHAVEN_SECURITY__KEYS='[{id="2027-01",secret_file="/run/secrets/davhaven-key-2027-01"}]'` and
`DAVHAVEN_SECURITY__ACTIVE_KEY_ID=2027-01`.

* **`id`**: 1 to 32 characters of `a-z`, `0-9`, `-` and `_`. It is stored next to every hash, signature and sealed value, so data
  stays verifiable after a rotation. Never reuse an id for another secret. A date is a good id.
* **The secret file** contains **one secret of at least 32 characters**, as the tool that made it prints it: the base64 or hex
  encoding of 32 or more random bytes. The server uses the text of the file (one trailing line break removed) as the key
  material as it is; it does **not** decode it. A shorter secret is refused at startup with the key id in the message, never the
  secret. Generate a key with either of

  ```sh
  openssl rand -base64 48 > davhaven-key-2027-01      # 64 characters
  openssl rand -hex 32 > davhaven-key-2027-01         # 64 characters
  ```

  and give it the permissions of any secret: readable by the user the container runs as (65532), by nobody else.
* **`active_key_id`** names the key used for everything new. The other keys only **verify and open** what was made with them.

`davhaven config check` reads every key file, so a missing, unreadable or short secret fails in the pipeline and not at the first
request. Production refuses to start without at least one key. Development mode makes up a key ring for the process when none is
configured; credentials made by one development process cannot be verified by another, which is why `admin bootstrap` and
`admin rotate-keys` refuse to run without `security.keys`.

## Rotating the active key

Rotation moves new data to a new key while the old key keeps verifying what it made. Do it on a schedule and whenever a person who
had access to a key leaves.

1. **Generate** the new key file and mount it next to the old one.
2. **Add the new key and keep the old key active.** Add the entry to `security.keys` and deploy. With more than one instance
   this step comes first on purpose: during the rolling update an old instance that does not know the new key would reject
   what a new instance signed (cursors, CSRF tokens). A deployment with one instance can skip to the next step.
3. **Make the new key active**: set `security.active_key_id` and deploy. New credentials, links, signatures and sealed values use
   the new key; everything made before keeps working because the old key is still listed. While the rollout runs, the instances
   disagree on the active key: an instance that still names the old key moves a credential that is used back to it, and one that
   names the new key moves it forward again. Each move is a compare-and-set that succeeds, writes a row and logs
   `a credential was moved to the active pepper key`, so a credential that is used during the rollout can change keys more than
   once. That is harmless (both keys verify throughout) and ends with the rollout: keep the mixed state short, and do not leave
   an instance on the old key for days.
4. **Reseal the stored secrets**: run `davhaven admin rotate-keys` once. The work belongs to the application, not to the
   command: every module that seals a column contributes a resealer (`davhaven_app::maintenance::keys`), and a test fails for a
   sealed column that has neither a resealer nor a guard (nor an entry for values that live for minutes), so a new kind of secret cannot
   ship without being covered. Today the resealers are the signing secrets of webhook subscriptions (the current and the previous
   one) and the OAuth tokens of external provider accounts. It seals every such secret that
   is under another key again under the active one, per tenant in one transaction, writes a `keys.rotated` audit record for each
   tenant where it changed something, and prints how many secrets it resealed and how many were current already (counted per
   secret: a subscription with a current and a previous secret has two; an account has one document of tokens). It can be repeated, and a run that was interrupted is
   finished by the next one. A secret that cannot be resealed (its key is not in the ring, or the subscription changed during
   the run) is counted as failed, logged with the subscription and left as it is, and the command exits 1: keep the retired key
   until a run reports no failure. Two kinds of secret need a word:
   * **External provider accounts**: the access and refresh tokens of a connected Google or Microsoft account are one sealed
     document per account, bound to the tenant and the account. An account that is being pulled while the run reseals it loses
     the race (it counts as failed, and the next run reseals it): run the command again until it reports no failure.
   * **OAuth states** (the PKCE verifier of a login that is in progress) are single-use and valid for ten minutes: wait that long
     after the rotation before you remove the retired key. A person who is at the consent screen of a provider while the active
     key changes finds their state unknown (it is a keyed hash under the active key) and starts again; nothing is lost.
5. **Let the credentials move, then retire the old key** when nothing depends on it any more (next section). Until then it
   stays in `security.keys`.

## Retiring a key

A key can be removed from `security.keys` when no data refers to it:

* **Sealed secrets**: `admin rotate-keys` reports 0 failed, and a second run reports 0 resealed (every secret is current under
  the active key).
* **Credentials**: the hash of a credential records the key it was made with (`pepper_kid`). A credential that is **used** after
  the rotation is hashed again under the active key, once, at its first fresh verification (the server knows the plaintext only
  while the client presents it; a verification that the cache remembers does not count, so it happens at the latest five
  minutes after the first request). A client that syncs every few minutes has moved within the hour; the credentials nobody
  used since the rotation still name the old key, and so do **system tokens** (they belong to no tenant and are not moved).
  The rule for retiring: **remove the old key when no live credential names it**, which the owner role can read:

  ```sql
  SELECT 'app_passwords' AS credential, pepper_kid, count(*) AS live
    FROM app_passwords WHERE revoked_at IS NULL GROUP BY pepper_kid
  UNION ALL
  SELECT 'api_tokens', pepper_kid, count(*)
    FROM api_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) GROUP BY pepper_kid
  UNION ALL
  SELECT 'feed_tokens', pepper_kid, count(*) FROM feed_tokens WHERE revoked_at IS NULL GROUP BY pepper_kid
  UNION ALL
  SELECT 'rsvp_tokens', pepper_kid, count(*)
    FROM rsvp_tokens WHERE revoked_at IS NULL AND expires_at > now() GROUP BY pepper_kid
  ORDER BY 1, 2;
  ```

  Whatever still names the old key when you remove it **stops verifying**: a client that has not connected since the rotation
  has to be given a new app password or token. So wait as long as a client may stay silent (a phone that is off for a
  fortnight), or revoke the idle credentials first (`last_used_at` is in the listings) and reissue what is still wanted. Recreate
  the system tokens (`admin system-token create`, after revoking the old one) before you remove the key they name. RSVP links
  move when their link is opened; the ones nobody opened die with the key, as described below.
* **RSVP links** in mails that were sent before stay valid under their stored hashes until they expire; once the key is removed the
  links of the old key stop working (an attendee asks for a new link by getting the next update of the invitation). Wait for the
  last event whose invitations were mailed before the rotation to end, plus seven days, or accept that those links die.
* Cursors, CSRF tokens and cached verifications are short-lived and need no action.

## If a key is compromised

1. Generate a new key, add it and make it active (steps 1 to 3 above, in one deployment).
2. Run `davhaven admin rotate-keys`. This protects the stored secrets from a copy of the database taken from now on; a copy
   taken before is still readable with the leaked key, so also **rotate the webhook secrets themselves** through the API
   (`POST /api/v1/tenants/{tenant}/webhooks/{id}/rotate-secret`) and tell the receivers.
3. **Remove the leaked key from `security.keys`**. This is the revocation: every credential hashed under it stops verifying and
   every RSVP link of it dies. Clients have to be given new app passwords; plan the communication before you do it.
4. Review the audit log (`GET /api/v1/tenants/{tenant}/audit-events`, scope `audit:read`) for the time the key was exposed.

## Backups

Back up the key files with the secrets of the deployment, **not** with the database dumps (a backup of both is a backup of everything
the keys protect). A restore of the database without the keys leaves the instance running but with no working credential and no
openable webhook secret. [`backup.md`](backup.md) says what else a restore needs.

## The certificate that signs Apple profiles

This is not a key of the ring, but it is a key of the deployment, so it is kept here. An Apple configuration profile (the
`.mobileconfig` that `POST …/client-config/apple-mobileconfig` returns) installs unsigned, but iOS and macOS then show it as
"Not Verified". With a certificate that chains to a root the device trusts, they show the name of the certificate instead.
Signing is **off** unless the deployment names a certificate and its key:

```toml
[security.profile_signing]
certificate_file = "/etc/davhaven/profile-signing/fullchain.pem"   # the certificate of the signer first, then its chain
private_key_file = "/etc/davhaven/profile-signing/privkey.pem"     # PKCS#8 or PKCS#1 RSA, RSA or ECDSA P-256, not encrypted
```

`/etc/davhaven/profile-signing/` is a **directory** that the container mounts from where the ACME client writes its output (see
"Mounting the files" below). Both settings may also name **one file**, a combined PEM with the key and then the chain with the
leaf first (some clients and secret stores write that form):

```toml
[security.profile_signing]
certificate_file = "/etc/davhaven/profile-signing/combined.pem"
private_key_file = "/etc/davhaven/profile-signing/combined.pem"
```

A combined file is read once, and it is replaced as a whole by the client, so a renewal never meets a moment in which the
certificate and the key do not fit.

* **Which certificate.** Any certificate whose chain the devices trust. The TLS certificate of the server (the
  `fullchain.pem` and `privkey.pem` of an ACME client) works and is what most deployments use; a code-signing or S/MIME
  certificate of a public CA works too. The software ships none and generates none: the certificate is the deployment's.
* **Checked at the start.** The files are read when the server starts and by `davhaven config check`: a key that does not
  belong to the first certificate, an encrypted key, a key in the SEC1 form (`BEGIN EC PRIVATE KEY`, convert it with
  `openssl pkcs8 -topk8 -nocrypt`) or a file without a certificate stops the start with a message that names the file and
  never quotes key material.
* **Mounting the files: mount the directory.** A renewal reaches the server only if the file it replaces is the file the server
  opens. An ACME client replaces `fullchain.pem` and `privkey.pem` by an atomic rename, which puts a new file under the name;
  the server opens the name again and finds it. That works for a **directory** that is mounted into the container (a bind
  mount of the host directory, a volume, a Kubernetes secret or ConfigMap volume without `subPath`, whose files are links that the
  kubelet swaps). It does **not** work where the mount pins the file that was there when the container started, because the
  container keeps looking at the old file for ever: a single file that is bind-mounted into the container on its own
  (`-v /host/fullchain.pem:/etc/davhaven/fullchain.pem`), a Docker Compose or Swarm secret (they appear as single files under
  `/run/secrets/`), and a Kubernetes volume that is mounted with `subPath`. There the renewal needs a restart of the
  container, and nothing in the server can tell that it missed it, except the expiry gauge below, which keeps the old date.
  Mount the directory instead and point the settings at the files in it.
* **Renewal needs no restart** when the directory is mounted. An ACME client renews the certificate about every 60 days. The
  server looks at the files again about once a minute (by its clock) and reads them only when their metadata changed: the
  length, the modification time and, on Linux, the device, the inode and the change time, which a rename changes whatever the
  modification time says (a link that is swapped, as in a mounted Kubernetes secret, counts too: the check follows links). A
  renewed certificate is in use within a minute of the change, and a profile signed after that carries it. A profile that was
  installed keeps its signature; it is replaced the next time the person installs a new one. A certificate that has expired
  makes the devices show the profile as expired, so renew it with the rest of the certificates; `davhaven config check` and
  the start warn when the certificate has run out or runs out within 14 days. Files that were only touched or copied again, with
  the same certificates and the same key, change nothing.
* **A pair that cannot be used is not taken.** With two files, the client renames them one after the other, so for a moment the
  new certificate meets the old key; a file can be empty, half written or not a PEM file; the new certificate can have ended
  already, or not say when it ends. The server then keeps signing with the pair in use, logs the warning `the profile signer
  keeps the certificate in use` with the reason (it names the key and the file and never contains key material), and counts a
  failed pass of the worker `profile_signing` (`davhaven_worker_passes_total{worker="profile_signing",outcome="failed"}`) at
  every check for as long as the files stay as they are. A pair that was read and refused is not read again until its files
  change, so the second rename of a renewal is looked at at once; a file that cannot be read at all is tried again at every
  check. A warning that does not go away within a few minutes is a real problem: the files do not belong together, or the client
  wrote something else. The log line `the profile signer picked up a renewed certificate` (with the new end of validity) says
  that a renewal is in use.
* **A check that hangs shows.** A file system that does not answer (a mount that went away) cannot stall signing, which never
  waits for a file. The check ends its pass after 30 seconds as a failed pass with a warning, and so does every pass after it
  that finds the check still running, for as long as the mount stays hung: look at
  `davhaven_worker_passes_total{worker="profile_signing",outcome="failed"}`.
* **Watching the certificate.** `davhaven_profile_signing_certificate_expiry_timestamp_seconds` is the end of the validity
  (`notAfter`) of the first certificate of the file, the one that signs, in unix seconds. It follows a renewal within a minute,
  keeps the value of the certificate in use while a new pair is refused, and is absent while signing is off. The shipped alert
  `DavhavenProfileSigningCertificateExpiring` fires when the certificate in use ends within 14 days, that is, when a renewal
  does not arrive or does not reach the server ([`runbook.md`](runbook.md#davhavenprofilesigningcertificateexpiring)); ACME
  clients renew 30 days before the end, so the certificate in use should never be that close.
* **What is signed.** The profile as it is (the app password stays in it: the answer is still `no-store`), as a CMS
  `SignedData` with the profile inside, the signing time from the server's clock and SHA-256. Turn the option off and the next
  profile is the plain property list again.
