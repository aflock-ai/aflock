# signed-policy-demo

End-to-end example showing how a `.aflock` policy is signed via Sigstore
keyless (Fulcio) and verified at load time against an operator-controlled
`aflock-trust.json`.

## Files

- `.aflock` — the policy itself (rules: tool allowlist, file allowlist, limits).
- `aflock-trust.json` — declares the OIDC issuer + subject pattern that signed
  policies must come from. **Edit the placeholder before using.**
- `.aflock.signed` — produced by `aflock sign`. The DSSE envelope containing
  the policy bytes, the Fulcio leaf cert bound to your OIDC identity, and the
  signature. Not checked into git in this template.

## Sign locally

The interactive browser flow uses Sigstore's Dex OIDC broker, which accepts
Google, GitHub, and Microsoft logins.

```sh
export FULCIO_OIDC_ISSUER=https://oauth2.sigstore.dev/auth
export FULCIO_OIDC_CLIENT_ID=sigstore

aflock sign examples/signed-policy-demo/.aflock \
  --output examples/signed-policy-demo/.aflock.signed
# → browser opens, you log in, Fulcio issues a ~10-min cert, signature written
```

If you have an OIDC token out-of-band, use `FULCIO_TOKEN=<jwt>` or
`FULCIO_TOKEN_PATH=<file>` instead.

## Configure trust

Edit `aflock-trust.json` so `subjectPattern` matches the identity you signed
with. For a Google login via Sigstore Dex, that's your email address:

```json
{
  "version": "1",
  "verifiers": [{
    "type": "sigstore",
    "issuer": "https://oauth2.sigstore.dev/auth",
    "subjectPattern": "you@gmail.com"
  }]
}
```

`subjectPattern` supports glob — `*@gmail.com` works too.

## Verify

```sh
aflock policy verify examples/signed-policy-demo/.aflock.signed
# → prints {issuer, subject, certNotBefore, certNotAfter, payloadType}
#   exits 0 on success, 1 on failure
```

## Run aflock against the signed policy

```sh
aflock serve --policy examples/signed-policy-demo/.aflock.signed
```

`policy.Load` detects the envelope, locates `aflock-trust.json` in the same
directory, verifies the Fulcio cert chains to the Sigstore root and matches
the trust config's issuer + subject pattern, then proceeds with the inner
policy.

## Caveat

This release does not yet wire TSA/Rekor SET into the envelope. Fulcio leaf
certs are ~10 minutes valid, so a `.signed` file goes stale once the cert
expires unless verification happens within that window. Re-sign close to
verification. Tracking issue: add TSA/Rekor SET support for long-lived
signed policies.
