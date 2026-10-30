# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy package-firewall sandbox image: nuget (.NET SDK 8).
#   Build context is control-plane/ (the Go module). Build via: make sandbox-images
# Ships a prebuilt .NET loader (AssemblyLoadContext that runs module initializers of the package's lib
# assemblies, ignoring missing references) and warms the SDK so the runtime build runs offline.

FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ENV GOFLAGS=-mod=readonly GOWORK=off CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG RUNNER_VERSION=3.0.0-dev
RUN go build -trimpath -ldflags "-s -w -X aegisproxy/control-plane/internal/sandbox/runner.Version=${RUNNER_VERSION}" \
      -o /out/aegis-runner ./cmd/aegis-sandbox-runner

FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:6ba9644da07bb5b560a402acec9ca38711a0762969f1b61da261df5c9f6f85da
ARG RUNNER_VERSION=3.0.0-dev
LABEL org.aegisproxy.sandbox.ecosystem="nuget" \
      org.aegisproxy.sandbox.runner-version="${RUNNER_VERSION}"
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Build the prebuilt .NET loader (inlined so the build context stays the Go module).
RUN mkdir -p /src/loader
RUN cat > /src/loader/AegisLoader.csproj <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>AegisLoader</AssemblyName>
  </PropertyGroup>
</Project>
EOF
RUN cat > /src/loader/Program.cs <<'EOF'
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;

// Harness that loads a package's lib assemblies and runs their module initializers (module .cctor), so a package
// whose code runs at load time is observed. Missing references resolve to nothing and the resulting errors are
// swallowed per assembly. argv[0] is the directory holding the assemblies.
class Program
{
    static int Main(string[] args)
    {
        try { var s = Environment.GetEnvironmentVariable("AEGIS_SENTINEL"); if (s != null && File.Exists(s)) File.ReadAllText(s); } catch { }
        if (args.Length < 1 || !Directory.Exists(args[0])) return 0;
        var ctx = new AssemblyLoadContext("aegis", isCollectible: false);
        ctx.Resolving += (c, name) => null;
        foreach (var dll in Directory.GetFiles(args[0], "*.dll"))
        {
            try
            {
                var asm = ctx.LoadFromAssemblyPath(Path.GetFullPath(dll));
                foreach (var mod in asm.GetModules())
                {
                    try { RuntimeHelpers.RunModuleConstructor(mod.ModuleHandle); }
                    catch (Exception e) { Console.Error.WriteLine("[aegis] cctor " + Path.GetFileName(dll) + ": " + e.Message); }
                }
            }
            catch (Exception e) { Console.Error.WriteLine("[aegis] load " + Path.GetFileName(dll) + ": " + e.Message); }
        }
        System.Threading.Thread.Sleep(2000);
        return 0;
    }
}
EOF
RUN dotnet publish /src/loader/AegisLoader.csproj -c Release -o /aegis/loader \
 && rm -rf /src/loader /tmp/NuGetScratch

# Warm an SDK-style net8.0 build with no package references so the runtime build (the generated stub that imports
# a package's build/*.props|targets) resolves purely from the bundled packs, offline.
RUN mkdir -p /tmp/warm \
 && printf '%s\n' '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>' > /tmp/warm/warm.csproj \
 && dotnet build /tmp/warm/warm.csproj -p:UseSharedCompilation=false --nologo -v quiet \
 && rm -rf /tmp/warm

RUN set -eux; \
    if id -u 1000 >/dev/null 2>&1; then userdel -rf "$(id -nu 1000)" 2>/dev/null || true; fi; \
    groupadd -g 1000 sandbox; \
    useradd -m -u 1000 -g 1000 -s /bin/sh sandbox; \
    mkdir -p /home/sandbox /aegis /work; \
    chown 1000:1000 /home/sandbox /work
COPY --from=build /out/aegis-runner /aegis/runner
ENTRYPOINT ["/aegis/runner"]
