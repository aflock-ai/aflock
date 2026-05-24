# signed-policy-demo

End-to-end example showing how a `.aflock` policy is signed by a CI workflow
identity (Sigstore keyless / Fulcio) and verified at load time against a
`aflock-trust.json` trust root.

## Files

- `.aflock` — the policy itself (rules: tool allowlist, file allowlist, limits).
- `aflock-trust.json` — operator-controlled trust root. Declares the OIDC
  issuer + subject pattern that signed policies must come from. In this demo
  the trusted signer is `.github/workflows/sign-policy.yml@refs/heads/*`.
- `.aflock.signed` — the DSSE envelope produced by the workflow. Contains the
  policy bytes, a Fulcio leaf cert bound to the workflow's OIDC identity, and
  the signature. Committed back to the repo by an automated PR.

## Sign locally (developer flow)

```sh
# Mint an OIDC token from your IdP (Google, GitHub, Microsoft, etc.) and
# point Fulcio at it. The interactive flow opens a browser:
aflock sign examples/signed-policy-demo/.aflock \
  --output examples/signed-policy-demo/.aflock.signed
```

You'll need either `GITHUB_ACTIONS=true` (only true in CI), `FULCIO_TOKEN=<jwt>`,
or `FULCIO_TOKEN_PATH=<file>` to be set.

## Sign in CI (the supported flow)

Edit `.aflock` and push to `main` or `dev`. The
[`sign-policy.yml`](../../.github/workflows/sign-policy.yml) workflow re-signs
the policy and opens a PR with the updated `.aflock.signed`.

## Verify

```sh
aflock policy verify examples/signed-policy-demo/.aflock.signed
# → {
#     "issuer":  "https://token.actions.githubusercontent.com",
#     "subject": "https://github.com/aflock-ai/aflock/.github/workflows/sign-policy.yml@refs/heads/main",
#     "certNotBefore": "...",
#     "certNotAfter":  "...",
#     "payloadType":   "application/vnd.aflock.policy+json"
#   }
```

## Run aflock against the signed policy

```sh
aflock serve --policy examples/signed-policy-demo/.aflock.signed
```

`policy.Load` detects the envelope, locates `aflock-trust.json` in the same
directory, verifies the Fulcio cert chains to the Sigstore root and that its
issuer+subject match the trust config, then proceeds with the inner policy.

## Caveat

This release does not yet wire TSA/Rekor SET into the envelope. Fulcio leaf
certs are ~10 minutes valid, so a `.signed` file goes stale once the cert
expires unless verification happens within the window. For long-lived signed
policies, follow the tracking issue (linked in the PR that introduced this
demo) — TSA support will let an envelope's signature outlive the cert.

In practice this means: re-sign close to verification. The CI workflow does
this automatically on every policy change; manual signing is only useful for
quick local tests.
