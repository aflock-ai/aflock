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

`subjectPattern` is exact-match on the cert SAN email (or URI for CI
identities) — wildcards do not match, pin the exact address.

## Verify

```sh
aflock policy verify examples/signed-policy-demo/.aflock.signed
# → prints {issuer, subject, certNotBefore, certNotAfter, payloadType}
#   exits 0 on success, 1 on failure
```

## Run aflock against the signed policy

The trust config in this directory is committed alongside the demo for
discoverability, but aflock does NOT pick it up automatically — that
fallback was removed because anyone who can write the policy can also
rewrite a policy-dir trust file. Point `$AFLOCK_TRUST_CONFIG` at it
explicitly, or copy it to `~/.aflock/trust.json`:

```sh
export AFLOCK_TRUST_CONFIG=$PWD/examples/signed-policy-demo/aflock-trust.json
aflock serve --policy examples/signed-policy-demo/.aflock.signed
```

`policy.Load` detects the envelope, loads the trust config from the
operator-pinned location, verifies the Fulcio cert chains to the Sigstore
root and matches the trust config's issuer + subject pattern, then proceeds
with the inner policy.

## Persistence

The envelope bundles a Sigstore TSA timestamp, so verification uses the
TSA-attested signing time rather than `time.Now()` when checking the Fulcio
cert's validity. A `.signed` file committed today still verifies months from
now. Re-sign only when the policy itself changes.
