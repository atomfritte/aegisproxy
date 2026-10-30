// Generates ../npm.json from node-semver and npm-package-arg (the versions npm bundles):
//
//   node testdata/gen/npm.js > testdata/npm.json
//
// NPM_DIR is npm's installation directory (default /usr/lib/node_modules/npm); semver is resolved the way
// npm-package-arg resolves it.
'use strict'
const npmDir = process.env.NPM_DIR || '/usr/lib/node_modules/npm'
const npaDir = `${npmDir}/node_modules/npm-package-arg`
const npa = require(npaDir)
const semver = require(require.resolve('semver', { paths: [npaDir] }))
const semverVersion = require(require.resolve('semver/package.json', { paths: [npaDir] })).version

const versions = [
  '0.0.0', '0.0.0-foo', '0.0.1', '0.1.0', '0.9.0', '0.9.9', '0.10.0', '0.99.0', '1.0.0', '1.2.3', '2.0.0',
  'v0.0.0', 'v1.0.0', '=1.2.3', 'v 1.2.3', '= 1.2.3', ' v1.2.3', ' =1.2.3', ' v 1.2.3', ' = 1.2.3', '==1.2.3',
  'vv1.2.3', '=v1.2.3', 'v=1.2.3', '\t1.2.3\n', '\u00a01.2.3\u2003', '\ufeff1.2.3',
  '1.2.3-asdf', '1.2.3-4', '1.2.3-4-foo', '1.2.3-5-foo', '1.2.3-5', '1.2.3-5-Foo', '2.7.2+asdf', '3.0.0',
  '1.2.3-a.10', '1.2.3-a.5', '1.2.3-a.b', '1.2.3-a', '1.2.3-a.b.c.10.d.5', '1.2.3-a.b.c.5.d.100', '1.2.3-r2',
  '1.2.3-r100', '1.2.3-R2', '1.2.3-beta+build', '1.2.3+build', '1.2.3+otherbuild', '1.0.0-alpha',
  '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1',
  '1.0.0-0', '1.0.0-00', '1.0.0-01', '1.0.0-0a', '1.0.0--', '1.0.0-a-', '1.0.0-1.0', '1.0.0-1.0.0',
  '01.2.3', '1.02.3', '1.2.03', '1.2', '1', '1.2.3.4', '1.2.3-', '1.2.3+', '1.2.3-+a', '1.2.3-a..b',
  '1.2.3-a+b+c', '1.2.3-a_b', '1.2.3beta', '1.2.3 - 1.2.4', 'a.b.c', '', ' ', 'x', '1.x', '*',
  '9007199254740991.0.0', '9007199254740992.0.0', '0.0.9007199254740991', '1.0.0-9007199254740991',
  '1.0.0-9007199254740992', '1.0.0-99999999999999999999', '1.0.0-18446744073709551616', '1.2.3-ä',
  '1.2.3+ä', 'v' + '1'.repeat(20) + '.0.0', '1.0.0-' + 'a'.repeat(250), '1.0.0-' + 'a'.repeat(260),
  '0.0.0-0', '0.0.0-a', '99999.99999.99999', '1.2.3\n-beta', '1.2.3-beta\n', '1.2.3 ', '1.2.3  ',
]

// Range fixtures (most from node-semver's range-include / range-exclude tests) and edge cases.
const ranges = [
  '1.0.0 - 2.0.0', '^1.2.3+build', '1.2.3-pre+asdf - 2.4.3-pre+asdf', '1.2.3pre+asdf - 2.4.3-pre+asdf',
  '1.2.3-pre+asdf - 2.4.3pre+asdf', '1.2.3pre+asdf - 2.4.3pre+asdf', '1.2.3+asdf - 2.4.3+asdf', '1.0.0',
  '>=*', '', '*', '>=1.0.0', '>1.0.0', '<=2.0.0', '<2.0.0', '>= 1.0.0', '>=  1.0.0', '>=   1.0.0',
  '> 1.0.0', '>  1.0.0', '<=   2.0.0', '<= 2.0.0', '<=  2.0.0', '<    2.0.0', '<\t2.0.0', '>=0.1.97',
  '0.1.20 || 1.2.4', '>=0.2.3 || <0.0.1', '||', '2.x.x', '1.2.x', '1.2.x || 2.x', 'x', '2.*.*', '1.2.*',
  '1.2.* || 2.*', '2', '2.3', '~0.0.1', '~x', '~2', '~2.4', '~>3.2.1', '~1', '~>1', '~> 1', '~1.0',
  '~ 1.0', '~ 1.0.3', '~ 1.0.3alpha', '>=1', '>= 1', '<1.2', '< 1.2', '~v0.5.4-pre', '=0.7.x', '<=0.7.x',
  '>=0.7.x', '<0.7.x', '~1.2.1 >=1.2.3', '~1.2.1 =1.2.3', '~1.2.1 1.2.3', '~1.2.1 >=1.2.3 1.2.3',
  '~1.2.1 1.2.3 >=1.2.3', '>=1.2.1 1.2.3', '1.2.3 >=1.2.1', '>=1.2.3 >=1.2.1', '>=1.2.1 >=1.2.3', '>=1.2',
  '^1.2.3', '^0.1.2', '^0.1', '^0.0.1', '^1.2', '^1.2 ^1', '^1.2.3-alpha', '^1.2.0-alpha', '^0.0.1-alpha',
  '^0.1.1-alpha', '^x', 'x - 1.0.0', 'x - 1.x', '1.0.0 - x', '1.x - x', '<=7.x', '2.x', '1.1.x', '1.x',
  '^1.0.0-0', '^1.0.0-rc2', '^1.0.0', '1 - 2', '1.0 - 2', '>=1.0.0 <=1.1.0', '>=1.0.0 <1.1.0',
  '>=1.0.0 <1.1.0-pre', '^1.2.3-rc2', '>1.2', '<=1.2.3', '1', '<1', '< 1', '~v0.5.4-beta', '<1.2.3',
  '=1.2.3', '^0.0.0', '^0.0', '^0', '^0.0.x', '^0.x', '^0.x.x', '~0', '~0.0', '~0.0.0', '>01.02.03',
  '1.2.3-01', '^1.2.3-beta.4', '~>1.2', '<=1.2.3-alpha', '=v1.2.3', 'v1.2.3', '1.2.3 - 2.3.4 || 3.x',
  '>=1.2.3 || ~2', 'x.x.x', 'X', '1.X', '1.2.X', '1.*.3', '1.x.3', '*.2.3', '1.2.3 - *', '* - 1.2.3',
  '>1.x', '<1.x', '>=x', '<x', '>x', '<=x', '1.2.3 - 1.2', '1.2 - 1.2.3', '~1.2.3-beta', '>=1.2.3-beta',
  '>1.2.3-beta.1', '<1.2.3-beta.2 >1.2.3-beta.0', '1.2.3-beta.1 || 1.2.4-alpha', '^1.2.3-beta || ^2',
  '1.2.9007199254740992', '^9007199254740991.0.0', '~9007199254740991', '9007199254740991.x',
  '^9007199254740991', '>=1.0.0-alpha.9007199254740992', '1.0.0-99999999999999999999 - 2', 'blerg',
  'git+https://user:password0123@github.com/foo', '>=1.2.3 <=foo', '== 1.0.0 || foo', '1.2.3 || foo',
  'foo || 1.2.3', '>=1.0.0 || foo || <0.5.0', '1.0.0+build', '>=1.0.0+build <2.0.0+build', '~1.2.3+b',
  '1.2.3 -2.0.0', '1.2.3- 2.0.0', '1.2.3 -  2.0.0', '1.2.3  -  2.0.0', '1.2.3\t-\t2.0.0', ' 1.2.3 ',
  '>= 1.2.3 < 2.0.0', '>=\t1.2.3', '> =1.2.3', '>==1.2.3', '>=v1.2.3', '>=v 1.2.3', '>= v1.2.3',
  '~=1.2.3', '=~1.2.3', '^~1.2.3', '~^1.2.3', '^ 1.2.3', '^  1.2.3', '~  1.2.3', '1.2.3 ||2.0.0',
  '1.2.3|| 2.0.0', '1.2.3 | 2.0.0', '1.2.3 ||| 2.0.0', '|| 1.2.3', '1.2.3 ||', '>1 <1', '>1.0.0 <1.0.0',
  '<0.0.0-0', '<0.0.0', '>=0.0.0', '>=0.0.0-0', '*-beta', '^*', '~*', 'x.1', '1.x.x.x', '1.2.3.4',
  '>=1.2.3 <1.2.3', '1.2.3 1.2.4', '>1.2.3-alpha <1.2.3-beta', '\u00a01.2.3', '1.2.3\u00a0- 2.0.0',
  '>=1.2.3\u2003<2', '1.2.3\n|| 2', '^1.2.3\u3000', 'v', '=', '>', '<', '>=', '~', '^', '-', '1.2.3 -',
  '- 1.2.3', '1.2.3 - 2.0.0 - 3.0.0', 'latest', 'next', '^v1.2.3', '~>v1.2', 'v1.x', '=1', '=1.x',
  '1.2.3+build - 2.0.0', '>1.2.3+build', '1.0.0 - 1.0.0', '^0.0.1-beta', '~0.0.1-beta', '0.x || 1.x',
  '^1.0.0 || ^2.0.0 || ^3.0.0', '>=1 <2 || >=3 <4', '1.2.x 1.2.3', '>=1.0.0-0', '>=1.0.0-0 <2.0.0-0',
]

const pool = [
  '0.0.0', '0.0.0-a', '0.0.1', '0.0.1-beta', '0.0.2', '0.0.2-alpha', '0.0.3', '0.0.9', '0.1.0',
  '0.1.0-alpha', '0.1.1-beta', '0.1.2', '0.1.20', '0.1.93', '0.1.97', '0.2.2', '0.2.3', '0.2.4', '0.2.9',
  '0.5.4', '0.5.4-alpha', '0.5.5', '0.6.2', '0.7.0-asdf', '0.7.2', '0.8.2', '0.9.7', '1.0.0-a', '1.0.0-pre',
  '1.0.0-rc1', '1.0.0', '1.0.1', '1.0.1-rc1', '1.0.2', '1.0.12', '1.1.0-a', '1.1.0-pre', '1.1.0-rc1',
  '1.1.0', '1.1.1', '1.1.1-a', '1.1.3', '1.1.9', '1.2.0-a', '1.2.0-alpha', '1.2.0-pre', '1.2.0', '1.2.2',
  '1.2.3-alpha', '1.2.3-beta', '1.2.3-beta.0', '1.2.3-beta.1', '1.2.3-beta.2', '1.2.3-beta.4', '1.2.3-pre',
  '1.2.3-pre.2', '1.2.3', '1.2.4-alpha', '1.2.4', '1.2.8', '1.3.0-beta', '1.3.0', '1.3.3', '1.4.2', '1.8.1',
  '1.9.7', '1.9999.9999', '2.0.0-a', '2.0.0-alpha', '2.0.0-pre', '2.0.0-pre.0', '2.0.0-rc1', '2.0.0',
  '2.0.9', '2.1.0-pre.0', '2.1.2', '2.1.3', '2.2.3', '2.2.9', '2.3.1', '2.3.9', '2.4.0', '2.4.1',
  '2.4.3-alpha', '2.4.5', '2.5.0', '2.9999.9999', '3.0.0-pre', '3.0.0', '3.1.3', '3.2.0', '3.2.2', '3.3.2',
  '3.5.0', '4.0.0', '7.9.9', '9007199254740991.0.0', '9007199254740991.9007199254740991.9007199254740991',
]

const specs = [
  '', '*', 'latest', 'next', 'beta', '1.2.3', 'v1.2.3', '=1.2.3', '^1.0.0', '~1.2', '>=1 <2', '1.x', 'x',
  '1.2.3 - 2.0.0', '1 || 2', 'npm:lodash@^4', 'npm:@scope/pkg@1.0.0', 'npm:lodash', 'npm:lodash@latest',
  'npm:lodash@', 'npm:lodash@npm:foo@1', 'npm:lodash@github:u/r', 'npm:@scope/pkg', 'npm:@scope',
  'npm:./foo', 'npm:foo/bar', 'npm:https://x.com/a.tgz', 'npm:foo@file:../x', 'npm:Foo@1', 'npm:.foo@1',
  'npm:foo bar@1', 'NPM:lodash@1', 'github:user/repo', 'github:user/repo#v1.0', 'gitlab:user/repo',
  'bitbucket:user/repo', 'gist:11081aaa281', 'sourcehut:~user/repo', 'user/repo', 'user/repo#semver:^1.0',
  'user/repo#main', 'user/repo/', 'user/repo/extra', '@scope/pkg', '@scope/pkg@1', 'git+ssh://git@github.com/user/repo.git',
  'git+https://github.com/user/repo.git#main', 'git://github.com/user/repo.git', 'git@github.com:user/repo.git',
  'git@example.com:user/repo.git', 'git+ssh://git@example.com:user/repo.git', 'git+file:///tmp/repo',
  'ssh://git@github.com/user/repo.git', 'https://github.com/user/repo', 'https://github.com/user/repo.git',
  'https://gitlab.com/user/repo.git', 'https://bitbucket.org/user/repo.git', 'https://git.sr.ht/~user/repo',
  'https://example.com/pkg.tgz', 'http://example.com/pkg.tgz', 'https://example.com/pkg', 'HTTPS://example.com/a.tgz',
  'file:../local', 'file:pkg.tgz', 'file:', 'FILE:../x', './local', '../local', '.', '..', '/abs/path',
  '~/home/path', '~user/path', 'pkg.tgz', 'pkg.tar.gz', 'pkg.tar', 'foo/bar.tgz', 'workspace:*',
  'workspace:^1.0.0', 'link:../foo', 'catalog:', 'catalog:react18', 'jsr:@std/path', 'patch:foo@1.0.0#./patch',
  'portal:../foo', 'not a valid tag!', 'tag with space', 'tag%20', 'tag/with/slash', 'C:\\path\\to',
  'C:/path', '\\\\server\\share', 'git+ftp://example.com/repo', 'git+rsync://example.com/repo', 'svn://x/y',
  'foo:bar', 'ftp://example.com/x.tgz', 'https://github.com/user/repo/archive/v1.tar.gz',
  'https://gitlab.com/user/repo/-/archive/v1/repo-v1.tar.gz', 'github:user', 'github:', 'git+https://github.com/user',
  '  ^1.2.3  ', '\t latest\n', 'Latest', 'v1', 'latest#x', 'a@b', '1.2.3-beta', '>=1.2.3-beta', '^1.2.3+build',
  'blerg', '~', '^', '1.2.3 || foo', 'foo || 1.2.3', '=', '@', '@@', '#', 'user/repo#', 'git+ssh://git@github.com:user/repo.git',
]

function compareMatrix (vs) {
  return vs.map(a => vs.map(b => '<=>'[semver.compare(a, b) + 1]).join(''))
}

const clean = versions.map(v => ({ in: v, clean: semver.clean(v) }))
const valid = [...new Set(clean.filter(c => c.clean !== null).map(c => c.clean))]

const rangeOut = ranges.map(r => {
  const valid = semver.validRange(r, { loose: true })
  const bits = (o) => pool.map(v => semver.satisfies(v, r, o) ? '1' : '0').join('')
  return {
    in: r,
    valid,
    sat: bits({ loose: true }),
    satPre: bits({ loose: true, includePrerelease: true }),
    max: semver.maxSatisfying(pool, r, { loose: true }),
  }
})

const specOut = specs.map(s => {
  try {
    const r = npa.resolve('x', s, '/tmp')
    const o = { in: s, type: r.type }
    if (r.type === 'alias') {
      o.name = r.subSpec.name
      o.sub = r.subSpec.type
      o.subSpec = r.subSpec.fetchSpec
    }
    if (r.type === 'git') o.committish = r.gitCommittish || (r.gitRange ? 'semver:' + r.gitRange : '')
    return o
  } catch (e) {
    return { in: s, error: e.code || e.message }
  }
})

// One array element per line keeps the vectors reviewable.
function emit (obj) {
  const fields = Object.entries(obj).map(([k, v]) => Array.isArray(v)
    ? ` ${JSON.stringify(k)}: [\n${v.map(x => '  ' + JSON.stringify(x)).join(',\n')}\n ]`
    : ` ${JSON.stringify(k)}: ${JSON.stringify(v)}`)
  return `{\n${fields.join(',\n')}\n}\n`
}

process.stdout.write(emit({
  generator: `node-semver ${semverVersion}, npm-package-arg ${require(`${npaDir}/package.json`).version}, ` +
    `node ${process.version}`,
  versions: clean,
  compareVersions: valid,
  compareMatrix: compareMatrix(valid),
  pool,
  ranges: rangeOut,
  specs: specOut,
}))
