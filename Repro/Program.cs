using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Repro;

internal static class Program
{
    private const int KeyCount = 1000;
    private const int MaxPrintedFailures = 3;
    private const string FixtureFileName = "short-d.jwk.json";

    /// <summary>
    /// The minimal example from the issue: a spec-compliant 1024-bit key whose d is 127 bytes (its first byte is zero).
    /// PS256 is used because IdentityModel allows keys smaller than 2048 bits for it, unlike RS256.
    /// </summary>
    private const string SnippetJwk = """
        {
          "kty": "RSA",
          "n": "ubQ1Gu7ceiHcuzF8W9qz6j9i5IQLncohSpy9wC42cymPGgDpJYMXo-72LvtnmIPMcknUiG3mimIiFtzS-Tru8QVL4e8vdgn7g6cyN0eAAztsFSCfzgRp6sMrtp1UrzSY-t8PJnRrxQEl87DHp2-qV9sFSHNF9PsF0UErO3dD6U8",
          "e": "AQAB",
          "d": "CqoziK-WkmeV6QmMd2LWpgo5ydWKJvKgXlFxFwVPCuEnGtR6uthaG7jpxxqpFFUgyrZMnxFZjiEk-ismzHseIn9bUlInUkBZrhkMNfCV9e0e3aDfSzNzwXNLdZsOz44HL_vtV7XKEbVanZ1ZmJF3jdwIAM5-D9PlyihqC0_50Q",
          "p": "_oyofsEFaTO6Q_X9KDYdY1iBro8ZvonlO3ris75plu3MhMIEIPqpc44XrGZyxqVOeX1tHNZzKeodK1ANxoYiZw",
          "q": "usMdtZZiKsJP2PidQfPUCWrtBr5U5Yd9x6VupygHFM4MbWx-ORAuTSv23hPQM_auHYr9R-Dw8U4U7OMlHPFA2Q",
          "dp": "dx3DS21v5sb6Bwt5p_OK1Q55wQHd_jfxOWBL7ejQ6HvnFMjlvbkOyrBXi6l1VFfO3TNAeBoyUg7oD3iquZfTSQ",
          "dq": "K1ghSwWN3vKd6XM5vBbEvTLNs-T0exjI_k7MsYq-qftwMu0dFk1FEbAEaWIbzhOQMVcSlV4FTVuby6aj9GWhcQ",
          "qi": "90Cdh_4zDLm5VTSuI_LRN-PXojEbrmbDLPoRZfycqsqh3DzB_LC8w4-jkN2Qjoeq6gsXkvrK7ZXVllFN1_ebGg"
        }
        """;

    private static readonly string[] s_privateNames = ["d", "p", "q", "dp", "dq", "qi"];

    public static int Main(string[] args)
    {
        var mode = args.Length > 0 ? args[0] : "released";

        var identityModelVersion = typeof(JsonWebKey).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        Console.WriteLine($"Mode:          {mode}");
        Console.WriteLine($"OS:            {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})");
        Console.WriteLine($"Runtime:       {RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"IdentityModel: Microsoft.IdentityModel.Tokens {identityModelVersion}");
        Console.WriteLine();

        return mode switch
        {
            "released" => RunRandomKeys(padded: false),
            "padded" => RunRandomKeys(padded: true),
            "fixture" => RunFixture(),
            "snippet" => RunSnippet(),
            "find-fixture" => FindFixture(),
            _ => throw new ArgumentException("Usage: Repro <released | padded | fixture | snippet | find-fixture>"),
        };
    }

    /// <summary>
    /// released: sign with the JsonWebKey as is (IdentityModel's CreateRsaParameters, unchanged).
    /// padded:   pad the values as proposed and sign with an RsaSecurityKey (simulates the fix).
    /// </summary>
    private static int RunRandomKeys(bool padded)
    {
        Console.WriteLine(padded
            ? $"Signing with {KeyCount} random RSA-2048 JWKs, RSAParameters padded as proposed (simulated fix)."
            : $"Signing with {KeyCount} random RSA-2048 JWKs through JsonWebKey (released IdentityModel).");
        Console.WriteLine();

        var shortCounts = s_privateNames.ToDictionary(name => name, _ => 0);
        var keysWithShortValue = 0;
        var failures = 0;
        var failuresOnShortKeys = 0;

        for (var i = 0; i < KeyCount; i++)
        {
            using var rsa = RSA.Create(2048);
            var jwk = new JsonWebKey(ToMinimalJwkJson(rsa.ExportParameters(includePrivateParameters: true), kid: $"key-{i}"));

            var shortNames = ShortValues(jwk);
            foreach (var name in shortNames)
            {
                shortCounts[name]++;
            }

            if (shortNames.Count > 0)
            {
                keysWithShortValue++;
            }

            try
            {
                Sign(padded ? new RsaSecurityKey(CreatePaddedRsaParameters(jwk)) { KeyId = jwk.Kid } : jwk, SecurityAlgorithms.RsaSha256);
            }
            catch (Exception ex)
            {
                failures++;
                if (shortNames.Count > 0)
                {
                    failuresOnShortKeys++;
                }

                if (failures <= MaxPrintedFailures)
                {
                    Console.WriteLine($"FAILURE #{failures} (key {i}, short values: {Describe(shortNames)}):");
                    PrintExceptionChain(ex);
                    Console.WriteLine();
                }
            }
        }

        if (failures > MaxPrintedFailures)
        {
            Console.WriteLine($"({failures - MaxPrintedFailures} further failures not printed)");
            Console.WriteLine();
        }

        Console.WriteLine("Summary");
        Console.WriteLine($"  Keys:                          {KeyCount}");
        Console.WriteLine($"  Keys with a short value:       {keysWithShortValue} ({Percent(keysWithShortValue)})");
        foreach (var name in s_privateNames)
        {
            Console.WriteLine($"    {name,-3} shorter than required:  {shortCounts[name]}");
        }

        Console.WriteLine($"  Signing failures:              {failures} ({Percent(failures)})");
        Console.WriteLine($"    of which on keys with a short value: {failuresOnShortKeys}");
        Console.WriteLine();
        Console.WriteLine(failures == 0 ? "RESULT: PASS (all keys signed)" : "RESULT: FAIL");

        return failures == 0 ? 0 : 1;
    }

    private static int RunFixture()
    {
        var path = Path.Combine(GetFixturesDirectory(), FixtureFileName);
        Console.WriteLine($"Loading {Path.GetFullPath(path)} through JsonWebKey and signing with RS256 (released IdentityModel).");
        return SignSingleKey(new JsonWebKey(File.ReadAllText(path)), SecurityAlgorithms.RsaSha256);
    }

    private static int RunSnippet()
    {
        Console.WriteLine("Loading the 1024-bit JWK from the issue through JsonWebKey and signing with PS256 (released IdentityModel).");
        return SignSingleKey(new JsonWebKey(SnippetJwk), SecurityAlgorithms.RsaSsaPssSha256);
    }

    private static int SignSingleKey(JsonWebKey jwk, string algorithm)
    {
        Console.WriteLine($"Short values: {Describe(ShortValues(jwk))}");
        PrintLengths(jwk);
        Console.WriteLine();

        try
        {
            Sign(jwk, algorithm);
            Console.WriteLine("RESULT: PASS (signed)");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("FAILURE:");
            PrintExceptionChain(ex);
            Console.WriteLine();
            Console.WriteLine("RESULT: FAIL");
            return 1;
        }
    }

    private static int FindFixture()
    {
        for (var attempt = 1; ; attempt++)
        {
            using var rsa = RSA.Create(2048);
            var parameters = rsa.ExportParameters(includePrivateParameters: true);
            if (parameters.D![0] != 0)
            {
                continue;
            }

            var json = ToMinimalJwkJson(parameters, kid: "short-d-repro-fixture", indented: true);
            var path = Path.Combine(GetFixturesDirectory(), FixtureFileName);
            File.WriteAllText(path, json + "\n");

            var jwk = new JsonWebKey(json);
            Console.WriteLine($"Found a key with short d after {attempt} attempt(s).");
            Console.WriteLine($"Short values: {Describe(ShortValues(jwk))}");
            PrintLengths(jwk);
            Console.WriteLine($"Wrote {Path.GetFullPath(path)}");
            return 0;
        }
    }

    /// <summary>
    /// The application code path. IdentityModel creates the RSA instance (and, for a JsonWebKey, calls
    /// CreateRsaParameters and RSA.ImportParameters) lazily on the first Sign, not in CreateForSigning.
    /// </summary>
    private static void Sign(SecurityKey key, string algorithm) =>
        key.CryptoProviderFactory
            .CreateForSigning(key, algorithm)
            .Sign("payload"u8.ToArray());

    /// <summary>The proposed change to JsonWebKey.CreateRsaParameters.</summary>
    private static RSAParameters CreatePaddedRsaParameters(JsonWebKey jwk)
    {
        var modulus = Decode(jwk.N);
        var halfLength = (modulus.Length + 1) / 2;

        return new RSAParameters
        {
            Modulus = modulus,
            Exponent = Decode(jwk.E),
            D = PadLeft(Decode(jwk.D), modulus.Length),
            P = PadLeft(Decode(jwk.P), halfLength),
            Q = PadLeft(Decode(jwk.Q), halfLength),
            DP = PadLeft(Decode(jwk.DP), halfLength),
            DQ = PadLeft(Decode(jwk.DQ), halfLength),
            InverseQ = PadLeft(Decode(jwk.QI), halfLength),
        };
    }

    private static byte[] PadLeft(byte[] value, int length)
    {
        if (value.Length >= length)
        {
            return value;
        }

        var padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    /// <summary>
    /// Serializes as RFC 7518 requires: every value is a Base64urlUInt using the minimum number of octets,
    /// i.e. leading zero bytes are stripped.
    /// </summary>
    private static string ToMinimalJwkJson(RSAParameters parameters, string kid, bool indented = false)
    {
        var jwk = new
        {
            kty = "RSA",
            kid,
            n = EncodeMinimal(parameters.Modulus!),
            e = EncodeMinimal(parameters.Exponent!),
            d = EncodeMinimal(parameters.D!),
            p = EncodeMinimal(parameters.P!),
            q = EncodeMinimal(parameters.Q!),
            dp = EncodeMinimal(parameters.DP!),
            dq = EncodeMinimal(parameters.DQ!),
            qi = EncodeMinimal(parameters.InverseQ!),
        };

        return JsonSerializer.Serialize(jwk, new JsonSerializerOptions { WriteIndented = indented });
    }

    private static string EncodeMinimal(byte[] value)
    {
        var start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        return Base64UrlEncoder.Encode(value[start..]);
    }

    private static byte[] Decode(string value) => Base64UrlEncoder.DecodeBytes(value);

    private static Dictionary<string, int> PrivateValueLengths(JsonWebKey jwk) => new()
    {
        ["d"] = Decode(jwk.D).Length,
        ["p"] = Decode(jwk.P).Length,
        ["q"] = Decode(jwk.Q).Length,
        ["dp"] = Decode(jwk.DP).Length,
        ["dq"] = Decode(jwk.DQ).Length,
        ["qi"] = Decode(jwk.QI).Length,
    };

    /// <summary>The length RSAParameters requires: D as long as Modulus, the rest half of that (rounded up).</summary>
    private static int RequiredLength(string name, JsonWebKey jwk)
    {
        var modulusLength = Decode(jwk.N).Length;
        return name == "d" ? modulusLength : (modulusLength + 1) / 2;
    }

    /// <summary>Returns the private values that decode to fewer bytes than RSAParameters requires.</summary>
    private static List<string> ShortValues(JsonWebKey jwk)
    {
        var lengths = PrivateValueLengths(jwk);
        return s_privateNames.Where(name => lengths[name] < RequiredLength(name, jwk)).ToList();
    }

    private static void PrintLengths(JsonWebKey jwk)
    {
        var lengths = PrivateValueLengths(jwk);
        Console.WriteLine("Decoded lengths (actual / required by RSAParameters):");
        Console.WriteLine($"  n   {Decode(jwk.N).Length,3}");
        foreach (var name in s_privateNames)
        {
            Console.WriteLine($"  {name,-3} {lengths[name],3} / {RequiredLength(name, jwk)}");
        }
    }

    private static void PrintExceptionChain(Exception exception)
    {
        var depth = 0;
        for (var current = exception; current is not null; current = current.InnerException)
        {
            var indent = new string(' ', 2 + depth * 2);
            var arrow = depth == 0 ? string.Empty : "---> ";
            Console.WriteLine($"{indent}{arrow}{current.GetType().FullName}: {current.Message}");
            depth++;
        }
    }

    private static string Describe(List<string> names) => names.Count == 0 ? "none" : string.Join(", ", names);

    private static string Percent(int count) => $"{100.0 * count / KeyCount:0.0}%";

    /// <summary>Finds fixtures/ whether run from the repository root (CI) or from Repro/ (locally).</summary>
    private static string GetFixturesDirectory()
    {
        for (var directory = new DirectoryInfo(Directory.GetCurrentDirectory()); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "fixtures");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new DirectoryNotFoundException("Could not find a 'fixtures' directory in the current directory or any parent.");
    }
}
