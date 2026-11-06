using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Repro;

internal static class Program
{
    private const int DefaultKeyCount = 1000;
    private const int MaxPrintedFailures = 3;
    private const string FixtureFileName = "short-d.jwk.json";

    private static readonly string[] s_privateNames = ["d", "p", "q", "dp", "dq", "qi"];
    private static readonly byte[] s_payload = Encoding.UTF8.GetBytes("identitymodel-rsa-jwk-padding-repro");

    public static int Main(string[] args)
    {
        var mode = args.Length > 0 ? args[0] : "released";
        PrintEnvironment(mode);

        return mode switch
        {
            "released" => RunRandomKeys(ParseCount(args), padded: false),
            "padded" => RunRandomKeys(ParseCount(args), padded: true),
            "fixture" => RunFixture(args.Length > 1 ? args[1] : null),
            "find-fixture" => FindFixture(),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine("Usage: Repro <released [count] | padded [count] | fixture [path] | find-fixture>");
        return 64;
    }

    private static int ParseCount(string[] args)
    {
        if (args.Length > 1 && int.TryParse(args[1], out var count) && count > 0)
        {
            return count;
        }

        return DefaultKeyCount;
    }

    private static void PrintEnvironment(string mode)
    {
        var identityModelVersion = typeof(JsonWebKey).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

        Console.WriteLine($"Mode:          {mode}");
        Console.WriteLine($"OS:            {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture})");
        Console.WriteLine($"Runtime:       {RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"IdentityModel: Microsoft.IdentityModel.Tokens {identityModelVersion}");
        Console.WriteLine();
    }

    // Modes

    /// <summary>
    /// released: sign through JsonWebKey (IdentityModel's CreateRsaParameters, unchanged).
    /// padded:   same kind of JWKs, but build RSAParameters with the proposed padding and sign through RsaSecurityKey.
    /// </summary>
    private static int RunRandomKeys(int count, bool padded)
    {
        Console.WriteLine(padded
            ? $"Signing with {count} random RSA-2048 JWKs, RSAParameters padded as proposed (simulated fix)."
            : $"Signing with {count} random RSA-2048 JWKs through JsonWebKey (released IdentityModel).");
        Console.WriteLine();

        var shortCounts = s_privateNames.ToDictionary(name => name, _ => 0);
        var keysWithShortValue = 0;
        var failures = 0;
        var failuresOnShortKeys = 0;

        for (var i = 0; i < count; i++)
        {
            var json = CreateRandomJwkJson(kid: $"key-{i}");
            var shortNames = ShortValues(json);
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
                if (padded)
                {
                    SignWithPaddedRsaSecurityKey(json);
                }
                else
                {
                    SignWithJsonWebKey(json);
                }
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
        Console.WriteLine($"  Keys:                          {count}");
        Console.WriteLine($"  Keys with a short value:       {keysWithShortValue} ({Percent(keysWithShortValue, count)})");
        foreach (var name in s_privateNames)
        {
            Console.WriteLine($"    {name,-3} shorter than required:  {shortCounts[name]}");
        }

        Console.WriteLine($"  Signing failures:              {failures} ({Percent(failures, count)})");
        Console.WriteLine($"    of which on keys with a short value: {failuresOnShortKeys}");
        Console.WriteLine();
        Console.WriteLine(failures == 0 ? "RESULT: PASS (all keys signed)" : "RESULT: FAIL");

        return failures == 0 ? 0 : 1;
    }

    private static int RunFixture(string? path)
    {
        path ??= Path.Combine(GetFixturesDirectory(), FixtureFileName);

        Console.WriteLine($"Loading fixture {Path.GetFullPath(path)} through JsonWebKey and signing (released IdentityModel).");
        var json = File.ReadAllText(path);

        var shortNames = ShortValues(json);
        Console.WriteLine($"Short values in fixture: {Describe(shortNames)}");
        PrintLengths(json);
        Console.WriteLine();

        if (!shortNames.Contains("d"))
        {
            Console.WriteLine("RESULT: INVALID FIXTURE (d is not shorter than n; regenerate with 'find-fixture')");
            return 2;
        }

        try
        {
            SignWithJsonWebKey(json);
            Console.WriteLine("RESULT: PASS (signature created and verified)");
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
        var directory = GetFixturesDirectory();

        for (var attempt = 1; ; attempt++)
        {
            using var rsa = RSA.Create(2048);
            var parameters = rsa.ExportParameters(includePrivateParameters: true);
            if (parameters.D![0] != 0)
            {
                continue;
            }

            var json = ToMinimalJwkJson(parameters, kid: "short-d-repro-fixture", indented: true);
            var path = Path.Combine(directory, FixtureFileName);
            File.WriteAllText(path, json + "\n");

            Console.WriteLine($"Found a key with short d after {attempt} attempt(s).");
            Console.WriteLine($"Short values: {Describe(ShortValues(json))}");
            PrintLengths(json);
            Console.WriteLine($"Wrote {Path.GetFullPath(path)}");
            return 0;
        }
    }

    // Signing

    /// <summary>The code path used by applications: JsonWebKey -> CryptoProviderFactory -> CreateRsaParameters.</summary>
    private static void SignWithJsonWebKey(string json)
    {
        var jwk = new JsonWebKey(json);
        SignAndVerify(jwk, json);
    }

    /// <summary>Simulates the proposed fix: pad the decoded values before handing them to RSAParameters.</summary>
    private static void SignWithPaddedRsaSecurityKey(string json)
    {
        var jwk = new JsonWebKey(json);
        var key = new RsaSecurityKey(CreatePaddedRsaParameters(jwk)) { KeyId = jwk.Kid };
        SignAndVerify(key, json);
    }

    private static void SignAndVerify(SecurityKey key, string json)
    {
        var factory = key.CryptoProviderFactory;
        var provider = factory.CreateForSigning(key, SecurityAlgorithms.RsaSha256);
        try
        {
            Verify(json, provider.Sign(s_payload));
        }
        finally
        {
            factory.ReleaseSignatureProvider(provider);
        }
    }

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

    /// <summary>Verifies independently of IdentityModel, using only the public key.</summary>
    private static void Verify(string json, byte[] signature)
    {
        var jwk = new JsonWebKey(json);
        using var rsa = RSA.Create(new RSAParameters { Modulus = Decode(jwk.N), Exponent = Decode(jwk.E) });
        if (!rsa.VerifyData(s_payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            throw new CryptographicException("Signature was created but does not verify.");
        }
    }

    // JWK helpers

    private static string CreateRandomJwkJson(string kid)
    {
        using var rsa = RSA.Create(2048);
        return ToMinimalJwkJson(rsa.ExportParameters(includePrivateParameters: true), kid);
    }

    /// <summary>
    /// Serializes as RFC 7518 requires: every value is a Base64urlUInt using the minimum number of octets,
    /// i.e. leading zero bytes are stripped.
    /// </summary>
    private static string ToMinimalJwkJson(RSAParameters parameters, string kid, bool indented = false)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = indented }))
        {
            writer.WriteStartObject();
            writer.WriteString("kty", "RSA");
            writer.WriteString("kid", kid);
            writer.WriteString("n", EncodeMinimal(parameters.Modulus!));
            writer.WriteString("e", EncodeMinimal(parameters.Exponent!));
            writer.WriteString("d", EncodeMinimal(parameters.D!));
            writer.WriteString("p", EncodeMinimal(parameters.P!));
            writer.WriteString("q", EncodeMinimal(parameters.Q!));
            writer.WriteString("dp", EncodeMinimal(parameters.DP!));
            writer.WriteString("dq", EncodeMinimal(parameters.DQ!));
            writer.WriteString("qi", EncodeMinimal(parameters.InverseQ!));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
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

    private static Dictionary<string, int> DecodedLengths(string json)
    {
        using var document = JsonDocument.Parse(json);
        var lengths = new Dictionary<string, int>();
        foreach (var name in s_privateNames.Prepend("n"))
        {
            lengths[name] = Decode(document.RootElement.GetProperty(name).GetString()!).Length;
        }

        return lengths;
    }

    private static int RequiredLength(string name, int modulusLength) =>
        name == "d" ? modulusLength : (modulusLength + 1) / 2;

    /// <summary>Returns the private values that decode to fewer bytes than RSAParameters requires.</summary>
    private static List<string> ShortValues(string json)
    {
        var lengths = DecodedLengths(json);
        var modulusLength = lengths["n"];
        return s_privateNames.Where(name => lengths[name] < RequiredLength(name, modulusLength)).ToList();
    }

    private static void PrintLengths(string json)
    {
        var lengths = DecodedLengths(json);
        var modulusLength = lengths["n"];
        Console.WriteLine("Decoded lengths (actual / required by RSAParameters):");
        Console.WriteLine($"  n   {modulusLength,3}");
        foreach (var name in s_privateNames)
        {
            Console.WriteLine($"  {name,-3} {lengths[name],3} / {RequiredLength(name, modulusLength)}");
        }
    }

    // Output helpers

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

    private static string Percent(int part, int total) => $"{100.0 * part / total:0.0}%";

    private static string GetFixturesDirectory()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, "fixtures");
                if (Directory.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        throw new DirectoryNotFoundException("Could not find a 'fixtures' directory in the current directory or any parent.");
    }
}
