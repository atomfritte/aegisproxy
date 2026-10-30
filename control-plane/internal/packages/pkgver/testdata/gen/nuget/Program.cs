// Generates ../../nuget.json from NuGet.Versioning (the copy the .NET SDK ships):
//
//   dotnet run --project testdata/gen/nuget --artifacts-path <tmp dir> > testdata/nuget.json
using System.Reflection;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using NuGet.Versioning;

string[] versions =
{
    "1.0", " 1.0.0 ", "1. 2", "+1.-0", "01.002.0003.0004", "1.0.0.0", "1.0.0-Beta.01", "1.0.0-beta+0001.a", "1",
    "1.2.3.4.5", "1.0.0-", "1.0.0+", "2147483648.0", "2147483647.0.0.2147483647", "1.0.0-a_b", "1.0-rc.1",
    "1.0 .0", "1.0.0-a+", "1.0.0-a.", "1.0.0+a..b", "1.0.0-+a", "1.0.0.1-beta", "1.0.0-0", "1.0.0-00",
    "1.0.0-0a", "v1.0", "1..0", ".1", "1.0.", " 1.0", "1.0.0-a-", "1.0.0--", "1.0.0-a+b+c", "1.0.0+b-c",
    "-1.0", "1.0.0-ä", "١.٠", "１.0", "1.0 .0", "1.0​.0", "1.0\u0085.0", "1.0.0-beta ",
    "1.0.0 -beta", "1 .0", "1\t.0", "1 .0-beta", "1.0 -beta", "1.0- beta", "1.0.0-beta +meta", "1. 0. 0. 0",
    "1.0.0-beta.-1", "1. ", " 1", "", " ", "1.0.0-alpha.1", "1.0.0-ALPHA", "1.0.0-rc.1+build.5", "1.0.0+build",
    "1.0.0.0+build", "1.0.0.1", "0.0.0", "0.0.0.0", "1.2.3-RC.1", "1.2.3-rc.01", "1.2.3+01", "1.2.3+-",
    "1.2.3-a.b.c.d.e.f", "1.2.3-123456789012", "1.2.3-0.0", "1.2.3-x.7.z.92", "4.0.0-beta-12345", "1.0.0-*",
    "1.*", "*", "1.0.0 ", "\t1.0.0\n", "1.0.0\r\n", "1.0.0.0.0", "1.0.0-a b", "1.0.0+a b",
};

string[] compare =
{
    "0.0.0", "0.0.1", "0.1.0", "1.0.0-0", "1.0.0--", "1.0.0--1", "1.0.0-1", "1.0.0-2", "1.0.0-10", "1.0.0-0a",
    "1.0.0-A", "1.0.0-a", "1.0.0-a.1", "1.0.0-a.2", "1.0.0-a.10", "1.0.0-a.-1", "1.0.0-a.b", "1.0.0-a-b",
    "1.0.0-a.2147483648", "1.0.0-a.3", "1.0.0-Z", "1.0.0-alpha", "1.0.0-ALPHA", "1.0.0-alpha.beta", "1.0.0-beta",
    "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.0+a", "1.0.0+b", "1.0.0.0", "1.0.0.1",
    "1.0.0.1-beta", "1.0.1-beta", "1.0.1", "1.0.10", "1.1", "1.10", "2.0.0-rc", "2.0.0", "10.0.0", "1.0.0-a.0",
    "1.0.0-a.-0", "1.0.0-a.-2147483648", "1.0.0-a.-2147483649", "1.0.0-a.2147483647",
};

string[] ranges =
{
    "1.0.0", "1.0", "1", "[1.0.0]", "[1.0]", "(1.0.0, )", "(1.0,)", "[1.0.0, 2.0.0)", "[1.0,2.0)", "(, 2.0.0]",
    "(,2.0]", "(,2.0)", "[1.0.0, 1.0.0]", "[1.0,1.0]", "(1.0,1.0)", "[1.0,1.0)", "(1.0,1.0]", "[2.0,1.0]",
    "(1.0)", "[1.0", "1.0]", "(1.0,]", "[1.0,)", "[,2.0]", "[,2.0)", "(,)", "[,]", "[ , ]", "[1.0,2.0,3.0]",
    "[ 1.0 , 2.0 ]", "  [1.0, 2.0]  ", "[1.0.0-beta, 2.0)", "(, 1.0.0-beta)", "[1.0.0-a+x, 2.0.0+y]",
    "1.0.0+meta", "[1.0.0+a,1.0.0+b)", "[1.0.0-beta,1.0.0-alpha]", "[1.0.0.0, 1.0.0]", "(1.0.0, 1.0.0.0)",
    "1.0.0.1", "[1.0.0.1, 2.0)", "1.0.0-beta", "1.0.0-beta.1", "~1.0", ">=1.0", "1.0 - 2.0", "1.0.0-", "",
    " ", "[]", "()", "[", "(", "abc", "[abc, 2.0)", "[1.0, abc)",
    // floating
    "*", " * ", "*-*", "1.*", "1.0.*", "1.0.0.*", "1.2.*", "1.2.3.*", "1.2.3.4.*", "1.0.0-*", "1.0-*", "1-*",
    "1.0.0-beta*", "1.0.0-beta.*", "1.0.0-beta-*", "1.0.0-a-b*", "1.0.0-a-*", "1.0.0--*", "1.2.3-beta*",
    "1.*-*", "1.2.*-*", "1.2.3.*-*", "1.2.3.4.*-*", "*-beta*", "*-*-*", "1.*-beta*", "1.*-1.*", "1.0.0-*.*",
    "1.0.0-a*b*", "1*", "10*", "1.2*", "*.*", "1.*.3", "1.0.*-beta", "1.0.0+meta*", "1.0.*+meta", "*-", "1.*-",
    "[1.*, 2.0)", "(1.*, 2.0)", "[ 1.*, 2.0)", "[1.* , 2.0)", "[1.0, 2.*)", "[1.*]", "[1.*, 1.0.0]",
    "[1.*, 0.9]", "(1.2.*, 1.0)", "[1.0.0-*, 2.0.0)", "(1.0.0.1-*, )", "1.0.0.1-*", "1.0.0.1-beta*",
    "1.2.3.4-*", "1.2.3.0-*", "[*, 2.0)", "[*-*, 2.0)", "[ *-*, 2.0)", "[1.0.0-beta.*, 2.0)", "0.*", "0.0.*",
    "2.*", "3.0.*", "1.0.1-*", "1.0.0-rc*", "1.0.0-RC*", "1.0.0-alpha*", "1.0.0-beta.1*", "1.1.0-*",
};

string[] pool =
{
    "0.1.0", "0.9.0", "1.0.0-alpha", "1.0.0-beta", "1.0.0-beta.1", "1.0.0-beta.2", "1.0.0-beta-2", "1.0.0-rc.1",
    "1.0.0-RC.2", "1.0.0", "1.0.0+meta", "1.0.0.1-beta", "1.0.0.1", "1.0.1-beta", "1.0.1", "1.0.2",
    "1.1.0-alpha", "1.1.0", "1.2.0", "1.2.3-beta", "1.2.3", "1.2.3.4", "1.2.3.5-beta", "1.9.9", "2.0.0-beta",
    "2.0.0", "2.0.1", "2.1.0", "3.0.0-rc.1", "3.0.0", "10.0.0", "10.1.0", "0.0.0-0", "0.0.1-beta",
};

// Pools for FindBestMatch: the full pool plus subsets that exercise the floating fallbacks.
string[][] matchPools =
{
    pool,
    new[] { "0.1.0", "0.9.0" },
    new[] { "2.0.0", "2.1.0", "3.0.0" },
    new[] { "0.9.0", "2.0.0", "3.0.0" },
    new[] { "1.0.0-beta", "1.0.0-alpha", "1.0.0-rc.1" },
    new[] { "1.0.1", "1.0.0", "1.0.2" },
    new[] { "3.0.0", "2.0.0", "1.0.0", "1.5.0", "1.4.0" },
    new[] { "1.0.0+b", "1.0.0+a", "1.0.0" },
    new[] { "0.0.1-beta", "1.0.0-beta.2", "1.1.0-alpha", "2.0.0-beta" },
    new[] { "1.2.3.4", "1.2.3.5", "1.2.3", "1.2.4" },
};

var output = new JsonObject
{
    ["generator"] = $"NuGet.Versioning {typeof(NuGetVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion}, .NET {Environment.Version}",
};

var vs = new JsonArray();
foreach (var s in versions)
{
    var o = new JsonObject { ["in"] = s };
    if (NuGetVersion.TryParse(s, out var v))
    {
        o["norm"] = v.ToNormalizedString();
        o["full"] = v.ToFullString();
        o["pre"] = v.IsPrerelease;
    }
    else
    {
        o["norm"] = null;
    }
    vs.Add(o);
}
output["versions"] = vs;

var cmpVersions = compare.Select(NuGetVersion.Parse).ToList();
output["compareVersions"] = new JsonArray(compare.Select(s => (JsonNode)JsonValue.Create(s)).ToArray());
output["compareMatrix"] = new JsonArray(cmpVersions.Select(a => (JsonNode)JsonValue.Create(string.Concat(
    cmpVersions.Select(b => "<=>"[Math.Sign(VersionComparer.Default.Compare(a, b)) + 1])))).ToArray());

var poolVersions = pool.Select(NuGetVersion.Parse).ToList();
output["pool"] = new JsonArray(pool.Select(s => (JsonNode)JsonValue.Create(s)).ToArray());
output["matchPools"] = new JsonArray(matchPools.Select(p =>
    (JsonNode)new JsonArray(p.Select(s => (JsonNode)JsonValue.Create(s)).ToArray())).ToArray());

var rs = new JsonArray();
foreach (var s in ranges)
{
    var o = new JsonObject { ["in"] = s };
    if (!VersionRange.TryParse(s, true, out var r))
    {
        o["norm"] = null;
        rs.Add(o);
        continue;
    }
    o["norm"] = r.ToNormalizedString();
    o["floating"] = r.IsFloating;
    var b = r.Float?.FloatBehavior;
    var preOK = (r.HasLowerBound && r.MinVersion.IsPrerelease) || (r.HasUpperBound && r.MaxVersion.IsPrerelease) ||
        b == NuGetVersionFloatBehavior.Prerelease || b == NuGetVersionFloatBehavior.PrereleaseMajor ||
        b == NuGetVersionFloatBehavior.PrereleaseMinor || b == NuGetVersionFloatBehavior.PrereleasePatch ||
        b == NuGetVersionFloatBehavior.PrereleaseRevision || b == NuGetVersionFloatBehavior.AbsoluteLatest;
    // Contains(v, includePrerelease) as pkgver defines it: within the bounds and, for a floating range, the float;
    // pre-releases only for pre-release bounds or floats unless included.
    bool InRange(NuGetVersion v) => r.Satisfies(v) && (!r.IsFloating || r.Float.Satisfies(v));
    o["contains"] = string.Concat(poolVersions.Select(v => InRange(v) && (preOK || !v.IsPrerelease) ? '1' : '0'));
    o["containsPre"] = string.Concat(poolVersions.Select(v => InRange(v) ? '1' : '0'));
    o["best"] = new JsonArray(matchPools.Select(p =>
        (JsonNode)JsonValue.Create(r.FindBestMatch(p.Select(NuGetVersion.Parse))?.ToFullString())).ToArray());
    rs.Add(o);
}
output["ranges"] = rs;

// One array element per line keeps the vectors reviewable.
var opts = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
var fields = output.Select(kv => kv.Value is JsonArray a
    ? $" {JsonSerializer.Serialize(kv.Key)}: [\n{string.Join(",\n", a.Select(x => "  " + x.ToJsonString(opts)))}\n ]"
    : $" {JsonSerializer.Serialize(kv.Key)}: {kv.Value.ToJsonString(opts)}");
Console.Out.Write("{\n" + string.Join(",\n", fields) + "\n}\n");
