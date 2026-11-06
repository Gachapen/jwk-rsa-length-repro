# IdentityModel RSA JWK padding repro

`Microsoft.IdentityModel.Tokens.JsonWebKey.CreateRsaParameters()` base64url-decodes the private RSA values
(`d`, `p`, `q`, `dp`, `dq`, `qi`) and passes the bytes to `RSAParameters` unchanged.

[RFC 7518 §2](https://datatracker.ietf.org/doc/html/rfc7518#section-2) requires every value to use the minimum
number of octets, so when a value happens to start with a zero byte, a spec-compliant JWK encodes it one byte
shorter. `RSAParameters`, however, requires `D` to be exactly as long as `Modulus`, and `P`, `Q`, `DP`, `DQ`,
`InverseQ` to be exactly `(Modulus.Length + 1) / 2` bytes.

- **Windows** (CNG) enforces those lengths, so signing with such a key fails with
  `CryptographicException: If D is present, it must have the same length as Modulus…`
- **Linux and macOS** accept the shorter values, so the same key works there.

A few percent of freshly generated RSA keys are affected (the exact share depends on the key generator; mostly `d`).

## What the repro does

`Repro` is a .NET 10 console app using `Microsoft.IdentityModel.Tokens` (pinned in `Repro/Repro.csproj`).

| Mode | What it does | Windows | Linux / macOS |
|---|---|---|---|
| `released [count]` | Generates `count` (default 1000) `RSA.Create(2048)` keys, serializes each as a spec-compliant JWK (leading zero bytes stripped), loads it with `new JsonWebKey(json)` and signs via `jwk.CryptoProviderFactory.CreateForSigning(jwk, RS256)`. | fails for the keys with a short value → exit 1 | passes → exit 0 |
| `padded [count]` | Same kind of keys, but builds `RSAParameters` with the proposed padding (`D` → `n.Length`, the rest → `(n.Length + 1) / 2`) and signs through `RsaSecurityKey`. Simulates the fix. | passes | passes |
| `fixture [path]` | Loads [`fixtures/short-d.jwk.json`](fixtures/short-d.jwk.json) through `JsonWebKey` and signs. Deterministic version of `released`. | fails | passes |
| `find-fixture` | Generates keys until `d` is shorter than `n` and writes it to `fixtures/`. | – | – |

Each mode prints the OS, runtime and IdentityModel version, the full exception chain for failures, and a breakdown
of which parameter was short. Every signature is verified with the public key independently of IdentityModel.

> The fixture is a throwaway key generated only for this repro. It is not used anywhere.

## Run it

```sh
dotnet run --project Repro -c Release -- fixture
dotnet run --project Repro -c Release -- released
dotnet run --project Repro -c Release -- padded
```

The [`repro` workflow](.github/workflows/repro.yml) runs all three on `windows-latest`, `ubuntu-latest` and
`macos-latest`. Expected result: Windows is red on `fixture` and `released` and green on `padded`; Ubuntu and
macOS are green on every step.

## Proposed fix

In `JsonWebKey.CreateRsaParameters`, left-pad `D` to `Modulus.Length` and `P`, `Q`, `DP`, `DQ`, `InverseQ` to
`(Modulus.Length + 1) / 2`, leaving values that are already at least that long unchanged. This is what .NET's own
PKCS#1 reader does
([`RSAKeyFormatHelper.Pkcs1.cs`](https://github.com/dotnet/runtime/blob/main/src/libraries/Common/src/System/Security/Cryptography/RSAKeyFormatHelper.Pkcs1.cs)).
See `CreatePaddedRsaParameters` in [`Repro/Program.cs`](Repro/Program.cs).
