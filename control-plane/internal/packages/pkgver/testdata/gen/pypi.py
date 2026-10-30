"""Generates ../pypi.json from pypa/packaging:

    python3 -I testdata/gen/pypi.py > testdata/pypi.json
"""

import json
import sys

import packaging
from packaging.markers import InvalidMarker, Marker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

VERSIONS = [
    # packaging's test_version.py VERSIONS and normalization cases
    "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12", "1.0b1.dev456", "1.0b2",
    "1.0b2.post345.dev456", "1.0b2.post345", "1.0b2-346", "1.0c1.dev456", "1.0c1", "1.0rc2", "1.0c3", "1.0",
    "1.0.post456.dev34", "1.0.post456", "1.1.dev1", "1.2+123abc", "1.2+123abc456", "1.2+abc", "1.2+abc123",
    "1.2+abc123def", "1.2+1234.abc", "1.2+123456", "1.2.r32+123456", "1.2.rev33+123456", "1!1.0.dev456",
    "1!1.0a1", "1!1.0a2.dev456", "1!1.0a12.dev456", "1!1.0a12", "1!1.0b1.dev456", "1!1.0b2",
    "1!1.0b2.post345.dev456", "1!1.0b2.post345", "1!1.0b2-346", "1!1.0c1.dev456", "1!1.0c1", "1!1.0rc2",
    "1!1.0c3", "1!1.0", "1!1.0.post456.dev34", "1!1.0.post456", "1!1.1.dev1", "1!1.2+123abc",
    "1!1.2+123abc456", "1!1.2+abc", "1!1.2+abc123", "1!1.2+abc123def", "1!1.2+1234.abc", "1!1.2+123456",
    "1!1.2.r32+123456", "1!1.2.rev33+123456",
    "1.0a", "1.0a.1", "1.0alpha1", "1.0-a1", "1.0_a1", "1.0.a1", "1.0ALPHA1", "1.0b", "1.0beta2", "1.0c",
    "1.0pre1", "1.0preview1", "1.0-rc-1", "1.0.rc.1", "1.0_RC_1", "1.0rc", "1.0post", "1.0.post", "1.0-post1",
    "1.0_post1", "1.0post1", "1.0rev1", "1.0r1", "1.0-r1", "1.0-1", "1.0-0", "1.0.dev", "1.0-dev1",
    "1.0_dev1", "1.0dev1", "1.0DEV", "1.0+ubuntu-1", "1.0+ubuntu_1", "1.0+UBUNTU.1", "1.0+001", "1.0+0",
    "1.0+00a", "1.0.0", "1.0.0.0", "1.00", "01.002", "v1.0", "V1.0", " 1.0 ", "\t1.0\n", "0!1.0", "00!1.0",
    "1.0a01", "1.0.post01", "1.0.dev01", "1.0-", "1.0+", "1.0+.", "1.0+a..b", "1.0+a.", "1..0", "1.0.",
    ".1.0", "1.0a1a1", "1.0.post1.post2", "1.0.dev1.dev2", "1.0-1-1", "1.0_1", "1.0.1", "foo", "", "1.0 a1",
    "1.0 ", "1.0+local version", "1!", "!1.0", "1!2!3", "1.0.a.1", "1.0-a.1", "1.0a.b", "1.0.post.dev",
    "1.0post-dev", "1.0-post-dev", "1.0.post_dev", "1.0a1.post2.dev3+local.4", "1.0rc1-1", "1.0rc1.1",
    "99999999999999999999.0", "1.0.0.0.0.0.0.0.1", "0", "0.0", "0.0.0", "1.0+Local-Ver_sion", "2.0.0+deadbeef",
    "1.0.0-rc.1", "1.0.0-beta.2", "1.0.0-alpha", "1.0a1+abc", "1.1.0dev1", "1.0.0c1", "１.0", "1.٠",
]

POOL = [
    "0.1", "0.9", "1.0.dev0", "1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.0", "1.0+local",
    "1.0+local.1", "1.0+1", "1.0.post1.dev1", "1.0.post1", "1.0.post2", "1.0.1", "1.1.dev1", "1.1a1", "1.1",
    "1.1+abc", "1.1.post1", "1.2", "1.3", "1.4.5a4", "1.4.5", "1.4.6", "1.5", "1.9.9", "2.0.dev1", "2.0a1",
    "2.0", "2.0.0", "2.0+deadbeef", "2.0.post1.dev1", "2.0.post1", "2.0.1", "2.1", "2.1.1", "2.2.0", "3.0",
    "1!0.5", "1!1.0", "1!2.0", "2!1.0", "1.0.0.0.1", "10.0", "3.12", "3.12.10",
]

SPECIFIERS = [
    "", "  ", "==2.0", "==2", "==2.0.0", "==2.0.0.0", "==2.*", "==2.0.*", "==2.1.*", "==1.*", "==1!2.*",
    "==1.0a1", "==1.0.post1", "==1.0+local", "==1.0+LOCAL.1", "==1.0+1", "!=2.0", "!=2.*", "!=1.0+local",
    "!=1.0", "<=2.0", ">=2.0", "<2.0", ">2.0", "<2.0.dev1", ">2.0.dev1", "<2.0.post1", ">2.0.post1",
    ">1.0.post1", ">1.0.post1.dev1", "<1.0.post1", ">1.0a1", "<1.0a1", "<1.0b1", ">=1.0a1", "<=1.0a1",
    ">1.0", "<1.0", ">=1.0", "<=1.0", "<=1.0.post1", ">=1.0.post1", "~=2.0", "~=2.0.0", "~=1.4.5a4", "~=1.4.5",
    "~=1.0.post1", "~=1.0.dev1", "~=1!1.0", "~=1", "~=1.0.*", "===lolwat", "===1.0", "===1.0.0", "===1.0+local",
    "===2.0", "==1!2.0", ">=1!0", ">=1!1.0", "<1!1.0", "== 1.0", ">= 1.0 , < 2", " >=1.0 ", ">=1.0,",
    ",>=1.0", ">=1.0,,<2", "foo", "==", "<", ">=1.0 <2", "== v1.0", "==1.0-1", "==1.0_post1", "==1.*.0",
    ">=1.0a", "<1.0.0.0.dev0", "==1.0.dev0", ">=0.0.dev0", "<=1.0.post1.dev1", ">=1.0,<2.0", ">=1.0,<2.0,!=1.5",
    ">=1.0,!=1.0.*", ">=1.0,<1.1.dev0", "<=1.0+local", ">=1.0+local", "<1.0+local", "~=1.0+local",
    "==1.0.*+local", "==1.0a1.*", "!=1.0.post1.*", "==1.0.dev1.*", ">1.0.*", "== 1.0.*", "==1.0 .*", "==1.0. *",
    "==v1.*", "==1.0.0.*", "==0.*", ">=2.0a1,<3", ">1.0,<1.0", "<=1.0,>=1.0", ">=1.0,<=1.0", "!=1.0,==1.0",
    ">1!0", "<2!0", "===1.0a1", ">=1.0.dev0", ">1.0.dev0", "<1.0.dev1", "<1.0rc1", "<=1.0rc1", "~=1.0rc1",
    "==1.0rc1", ">=3.12", "~=3.12", "~=3.12.0", "==3.12.*", "~=0.9", ">0.9,<1.0.dev0", ">=1.0\t,\t<2",
    "<1.0.0.0.1", ">=1.4.5a4,<1.4.6", "~=1.1a1", "~=1.1.dev1", ">1.0+local", "!=1.0+local.1", "==1.0+local.1",
    ">=10", "<10", "==10.*", ">=1.0 , != 1.1",
]

MARKERS = [
    'python_version >= "3.8"', 'os_name == "nt"', "os.name == 'posix'", 'sys_platform == "win32"',
    'platform_machine == "x86_64"', 'python_version < "3.10" and platform_system != "Windows"',
    'extra == "security"', 'extra == "Security_Extra"', '"tests" == extra', 'extra == "Foo.Bar"',
    'python_full_version >= "3.12.0rc1"', 'implementation_name == "cpython" or implementation_name == "pypy"',
    'platform_release >= "6"', 'platform_release ~= "6.8"', 'python_version ~= "3.12"', 'python_version === "3.12"',
    'python_version in "3.11 3.12"', 'python_version not in "3.8 3.9"', '"linux" in sys_platform',
    '"x86" in platform_machine', 'platform_version < "10"', 'os_name < "posix"', 'os_name > "nt"',
    'os_name <= "posix"', 'os_name >= "posix"', 'os_name ~= "posix"', 'os_name === "posix"',
    'python_version > "3.12.0"', 'python_version == "3.12.*"', 'python_version != "3.12.*"',
    'python_version == "3.1*"', 'python_version < "3.13" and (os_name == "nt" or sys_platform == "darwin")',
    '(python_version < "3.13" and os_name == "nt") or sys_platform == "darwin"', 'python_version == python_version',
    'os_name == sys_platform', '"3.12" == "3.12"', '"3.12" == "python_version"', 'extra == ""', 'extras',
    '"a" in extras', '"A_b" in extras', '"a" not in extras', '"b-c" in extras', '"test" in dependency_groups',
    'extras == "a"', '"a" == extras', 'python_implementation == "CPython"', 'platform.python_implementation == "CPython"',
    'platform.machine == "arm64"', 'platform.version == "x"', 'sys.platform == "linux"', 'os.name == "nt"',
    'python_version >= "3.8" and', 'python_version >= 3.8', 'python_version >= "3.8" or or', '(python_version >= "3.8"',
    'python_version >= "3.8")', 'foo == "bar"', 'python_version<"3.8"', 'python_version<"3.8"and os_name=="nt"',
    'os_name=="nt"or os_name=="posix"', 'python_version >= "3.8" AND os_name == "nt"', 'python_version not  in "3.8"',
    'python_version notin "3.8"', '"\\x41" == os_name', "os_name == 'it\\'s'", 'os_name == "a\\nb"',
    'implementation_version >= "3.12"', 'implementation_version >= "3.12.10.1"', 'platform_release == "10"',
    'platform_release >= "10.0"', 'platform_release > "5.15.0-generic"', 'python_full_version == "3.12.10"',
    'python_full_version < "3.12.10"', 'python_full_version > "3.12.9"', 'python_full_version >= "3.13.0a1"',
    'python_full_version == "3.13.0+local"', 'python_full_version >= "3.13"', '((os_name == "nt"))',
    'os_name == "nt" and ((sys_platform == "win32" or sys_platform == "cygwin"))',
    'os_name == "posix" and (sys_platform == "linux") and (platform_machine == "x86_64" or platform_machine == "aarch64")',
    'os_name == "a" or os_name == "b" and os_name == "c"', '(os_name == "a" or os_name == "b") and os_name == "c"',
    'os_name == "posix" or (os_name == "nt" and (python_version < "3" or extra == "win"))', '  os_name == "nt"  ',
    'os_name\t==\t"nt"', 'os_name == "nt" ; extra', '', ' ', '()', 'os_name', 'os_name ==', '== "nt"',
    'os_name == "nt" and or os_name == "posix"', 'os_name == "unterminated', "os_name == 'mixed\"", 'os_name == "x" or',
    'python_version > "3.9" and python_version <= "3.12"', 'python_version >= "3.12" and python_version < "3.12.1"',
    'platform_system == "Linux" and platform_machine != "aarch64"', 'sys_platform != "darwin"',
    'implementation_name != "pypy"', 'python_version < "3.12" or python_version >= "3.13"', '"nt" in os_name',
    '"ux" in sys_platform', '"Windows" not in platform_system', 'platform_version == "10.0.19045"',
    'python_version === "3.12.0"', 'python_full_version === "3.12.10"', 'python_version > "3"', 'python_version < "4"',
    'python_version == "3.12.0"', 'python_version != "3.12.0"', 'python_version <= "3.12"', 'python_version ~= "3.0"',
    'python_version ~= "3"', 'platform_release < "7"', 'platform_release ~= "24.0"', 'implementation_version === "3.12.10"',
]

# The Go side's DefaultPythonEnvironments plus variants for extras and versions; set-valued variables are
# comma-separated lists (frozensets for packaging).
BASE = {
    "implementation_name": "cpython", "implementation_version": "3.12.10", "os_name": "posix",
    "platform_machine": "x86_64", "platform_python_implementation": "CPython", "platform_release": "6.8.0",
    "platform_system": "Linux", "platform_version": "#1 SMP PREEMPT_DYNAMIC", "python_full_version": "3.12.10",
    "python_version": "3.12", "sys_platform": "linux",
}
ENVS = [
    BASE,
    {**BASE, "platform_machine": "aarch64"},
    {**BASE, "os_name": "nt", "sys_platform": "win32", "platform_system": "Windows", "platform_release": "10",
     "platform_version": "10.0.19045", "platform_machine": "AMD64"},
    {**BASE, "sys_platform": "darwin", "platform_system": "Darwin", "platform_release": "24.0.0",
     "platform_version": "Darwin Kernel Version 24.0.0", "platform_machine": "arm64"},
    {**BASE, "extra": "Security"},
    {**BASE, "python_version": "3.8", "python_full_version": "3.8.18", "implementation_version": "3.8.18",
     "extra": "tests"},
    {**BASE, "os_name": "nt", "sys_platform": "win32", "python_version": "3.13", "python_full_version": "3.13.0+",
     "extra": "win"},
    {**BASE, "extra": "foo-bar", "extras": "a,b_c", "dependency_groups": "test,dev"},
    {**BASE, "python_version": "3.13", "python_full_version": "3.13.0a1", "implementation_version": "3.13.0a1",
     "extra": "security_extra"},
]

REQUIREMENTS = [
    "name", "name>=3", "name>=3,<2", "name==1.0.org1", "name (==4)", "name[bar]>=3", "name[bar,baz]>=3",
    "name[bar, baz] >= 3", "name[Bar_Baz,bar-baz]", "name@ http://foo.com", "name @ https://example.com/name;extra=bar",
    'name; python_version>="3.3"', 'name>=1.0; os_name == "nt"', 'name @ https://x.com/y.whl ; extra == "a"',
    "name @ file:///absolute/path", "name[]", "name[", "name[bar", "name>=1.0,", "name (>=1.0", "name>=1.0)",
    "name ==1.0.*", "name ==1.0.*+local", "name ~=1", "name ~= 1.0", "name===arbitrary", 'name===arbitrary ; os_name=="nt"',
    "name >= 1.0 ; ", "name; ", "-name", "name-", "na.me_x-y", "Name.Is_Mixed", "name[extra]@ http://x",
    "name @http://x", "name @ ", 'name @ http://x ;os_name=="nt"', 'name @ http://x;os_name=="nt"',
    'name>=1.0;python_version<"3"', 'name  >=1.0  ,  <2.0  ;  python_version  <  "3"', "name==1.0 extra", "name 1.0",
    "name>=1.0 <2", "name<1.0+local", "name<=1.0.*", "name==v1.0", "name>=1!1.0", "name\t>=1", "  name  ",
    'name ; extra == "Foo"', 'name[Foo]; extra == "Bar_Baz"', "name @ git+https://github.com/x/y.git@v1.0#egg=y",
    "name (>=1.0) ; os_name == 'nt'", "name(>=1.0)", "name ( >= 1.0 , < 2 )", "name[a,b,a]", "name[a b]", "name[a,]",
    "name[,a]", "name[_a]", "name[a.b-c_d]", "name>=1.0;", "name;python_version>'3'", "name>1.0.post1", "name~=1.4.5a4",
    "name==1.0+local", "name!=1.0+local", "name>=1.0a1", "name===1.0 ; extra=='x'", "name===", "name==",
    "name ; python_version", "name ; (os_name == 'nt' or os_name == 'posix') and python_version >= '3'",
    "Name_With.Mixed-Case[Extra_One]>=1", "a", "1name", "name1", "n", "name.", "name_", "__name", "näme",
    "name>=1.0 ; os_name == 'nt' or", "name @ http://x ", "name @ http://x  ;  os_name == 'nt'", "name@http://x",
    "name>=1,<2,!=1.5,==1.*", "name ===foo bar", "name[a]@http://x;os_name=='nt'",
]

WHEELS = [
    "pip-24.0-py3-none-any.whl", "requests-2.32.3-py3-none-any.whl", "numpy-2.1.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    "foo-1.0-1-py2.py3-none-any.whl", "foo-1.0-1abc-py3-none-any.whl", "foo-1.0-01-py3-none-any.whl",
    "foo-1.0-abc-py3-none-any.whl", "Foo_Bar-1.0-py3-none-any.whl", "foo.bar-1.0-py3-none-any.whl",
    "foo__bar-1.0-py3-none-any.whl", "foo-bar-1.0-py3-none-any.whl", "foo-1.0-py3-none-any", "foo-1.0-py3-none.whl",
    "foo-1.0-1-2-py3-none-any.whl", "foo-1.0.0.dev1-py3-none-any.whl", "foo-1.0a1-py3-none-any.whl",
    "foo-1!1.0-py3-none-any.whl", "foo-v1.0-py3-none-any.whl", "foo-1.0_1-py3-none-any.whl", "foo-invalid-py3-none-any.whl",
    "foo-1.0-PY3-NONE-ANY.whl", "foo-1.0-py3..py2-none-any.whl", "foo-1.0-py3.-none-any.whl", "foo-1.0--none-any.whl",
    "foo-1.0-3py-none-any.whl", "foo-1.0-cp312-abi3-win_amd64.whl", "foo-1.0-cp312-cp312-macosx_11_0_arm64.whl",
    "foo-1.0-py3-none-any.WHL", "-1.0-py3-none-any.whl", "foo-1.0+local-py3-none-any.whl", "foo-1.0-py3-none-any .whl",
    "foo-1.0-py3-none-any.whl.metadata", "foo bar-1.0-py3-none-any.whl", "foo-1.0-1_2-py3-none-any.whl",
    "foo-1.0-py3-none-linux_x86_64.manylinux1_x86_64.whl", "foo-1.0-py3-none-.whl", "foo-1.0-pyé-none-any.whl",
]

SDISTS = [
    "foo-1.0.tar.gz", "foo-1.0.zip", "foo-bar-1.0.tar.gz", "Foo_Bar-1.0rc1.tar.gz", "foo-1.0.tar.bz2", "foo-1.0.tgz",
    "foo-1.0.TAR.GZ", "foo.tar.gz", "-1.0.tar.gz", "foo-.tar.gz", "foo-1.0-1.tar.gz", "foo-v1.0.zip",
    "foo-invalid.tar.gz", "foo-1.0", "foo-1.0.tar", "foo-1.0.tar.xz", "foo-1!1.0.post1.tar.gz", "foo-1.0+local.tar.gz",
]


def version_record(s):
    try:
        v = Version(s)
    except InvalidVersion:
        return {"in": s, "norm": None}
    return {"in": s, "norm": str(v), "pre": v.is_prerelease, "post": v.is_postrelease, "epoch": v.epoch,
            "release": list(v.release), "local": v.local, "public": v.public}


def bits(f, items):
    return "".join("1" if f(x) else "0" for x in items)


def specifier_record(s):
    try:
        ss = SpecifierSet(s)
    except InvalidSpecifier:
        return {"in": s, "valid": False}
    return {
        "in": s, "valid": True, "str": str(ss), "prereleases": ss.prereleases is True,
        "contains": bits(lambda v: ss.contains(v, prereleases=False), POOL),
        "containsPre": bits(lambda v: ss.contains(v, prereleases=True), POOL),
        "filter": [POOL.index(v) for v in ss.filter(POOL)],
    }


def lock_env(env):
    e = {"extra": "", **env}
    for k in ("extras", "dependency_groups"):
        e[k] = frozenset(x for x in e.get(k, "").split(",") if x)
    return e


def marker_record(s):
    try:
        m = Marker(s)
    except InvalidMarker:
        return {"in": s, "valid": False}
    results = []
    for env in ENVS:
        try:
            results.append(m.evaluate(lock_env(env), context="lock_file"))
        except Exception:  # UndefinedComparison, UndefinedEnvironmentName
            results.append(None)
    return {"in": s, "valid": True, "str": str(m), "eval": results}


def requirement_record(s):
    try:
        r = Requirement(s)
    except InvalidRequirement:
        return {"in": s, "valid": False}
    extras = sorted({canonicalize_name(e) for e in r.extras})
    return {"in": s, "valid": True, "name": canonicalize_name(r.name), "extras": extras,
            "specifier": str(r.specifier), "url": r.url or "", "marker": str(r.marker) if r.marker else ""}


def wheel_record(s):
    try:
        name, version, build, tags = parse_wheel_filename(s)
    except (InvalidWheelFilename, InvalidVersion):
        return {"in": s, "valid": False}
    return {"in": s, "valid": True, "name": name, "version": str(version), "build": list(build),
            "tags": sorted(str(t) for t in tags)}


def sdist_record(s):
    try:
        name, version = parse_sdist_filename(s)
    except (InvalidSdistFilename, InvalidVersion):
        return {"in": s, "valid": False}
    return {"in": s, "valid": True, "name": name, "version": str(version)}


def main():
    versions = [version_record(s) for s in VERSIONS]
    # pkgver limits numeric components to int64.
    valid = sorted({r["norm"] for r in versions if r["norm"] is not None and max(r["release"]) < 2**63})
    parsed = [Version(v) for v in valid]
    matrix = ["".join("<=>"[(a > b) - (a < b) + 1] for b in parsed) for a in parsed]
    out = {
        "generator": f"packaging {packaging.__version__}, python {sys.version.split()[0]}",
        "versions": versions,
        "compareVersions": valid,
        "compareMatrix": matrix,
        "pool": POOL,
        "specifiers": [specifier_record(s) for s in SPECIFIERS],
        "envs": ENVS,
        "markers": [marker_record(s) for s in MARKERS],
        "requirements": [requirement_record(s) for s in REQUIREMENTS],
        "wheels": [wheel_record(s) for s in WHEELS],
        "sdists": [sdist_record(s) for s in SDISTS],
    }
    # One array element per line keeps the vectors reviewable.
    fields = []
    for k, v in out.items():
        if isinstance(v, list):
            body = ",\n".join("  " + json.dumps(x, ensure_ascii=False) for x in v)
            fields.append(f" {json.dumps(k)}: [\n{body}\n ]")
        else:
            fields.append(f" {json.dumps(k)}: {json.dumps(v)}")
    sys.stdout.write("{\n" + ",\n".join(fields) + "\n}\n")


main()
