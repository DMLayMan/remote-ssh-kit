import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const exampleAddresses = new Set(['0.0.0.0', '100.80.0.1', '100.80.0.2', '100.90.2.3', '100.90.2.4']);
const allowedAddress = value => exampleAddresses.has(value) || /^(127\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(value);
const rules = [
  ['host-or-client-key', /(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-\S+)\s+AAAA[A-Za-z0-9+/=]{30,}/],
  ['key-fingerprint', /SHA256:[A-Za-z0-9+/]{30,}/],
  ['personal-home', /(?:\/(?:Users|home)\/[^\s/"'<>]+|[A-Za-z]:\\+(?:Users|Documents and Settings)\\+[^\\\s"']+)/],
  ['tailnet-name', /\b[\w.-]+\.ts\.net\b/i],
  ['device-name', /\b[\w-]+\.(?:local|lan)\b(?![\w.-])/i],
  ['access-token', /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,})\b/],
  ['credential-in-url', /https?:\/\/[^\s/]+:[^\s/@]+@/],
];
const privateName = value => /(?:^|\/)(?:setup(?:\.[^/]+)?\.json|[^/]*receipt\.json|client-acceptance\.json|client-key\.pub|id_(?:rsa|ed25519)(?:\.pub)?|[^/]+\.(?:pem|p12|pfx)|\.env(?:\.[^/]+)?)$/i.test(value) && !value.endsWith('setup.example.json');

export function inspectText(text, {name = '', privateTerms = []} = {}) {
  const findings = [];
  if (name) findings.push(...inspectText(name, {privateTerms}).map(f => ({...f, line: 0})));

  if (privateName(name)) findings.push({rule: 'private-file', line: 0});
  if (text.includes('\0')) return [...findings, {rule: 'binary-file', line: 0}];
  // Match private values in escaped strings too, without printing any value.
  const normalized = text.replace(/\\([.\\/])/g, '$1');
  for (const term of privateTerms) {
    if (normalized.toLowerCase().includes(term.toLowerCase()) || name.toLowerCase().includes(term.toLowerCase())) {
      findings.push({rule: 'private-denylist', line: 0});
      break;
    }
  }
  if (/-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP|ENCRYPTED)?\s*PRIVATE KEY(?: BLOCK)?-----[\s\\nrt"'+]{0,20}[A-Za-z0-9+/]{40,}/.test(text)) findings.push({rule: 'private-key', line: 0});
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const [rule, pattern] of rules) {
      if (pattern.test(line)) findings.push({rule, line: i + 1});
    }
    for (const match of line.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
      if (match[0].split('.').every(n => Number(n) <= 255) && !allowedAddress(match[0])) findings.push({rule: 'network-address', line: i + 1});
    }
    for (const match of line.matchAll(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g)) {
      if (!/^(?:[a-z0-9.-]+\.)?example\.(?:com|org|net)$/.test(match[1]) && !/^(?:users\.)?noreply\.github\.com$/.test(match[1])) findings.push({rule: 'personal-email', line: i + 1});
    }
  }
  return findings;
}

export function loadPrivateTerms(file, repo) {
  if (!file) return [];
  const real = fs.realpathSync(file), rel = path.relative(fs.realpathSync(repo), real);
  if (rel === '' || (!rel.startsWith('..' + path.sep) && rel !== '..' && !path.isAbsolute(rel))) throw Error('DENYLIST_MUST_BE_OUTSIDE_REPOSITORY');
  const stat = fs.statSync(real);
  if (process.platform !== 'win32' && ((stat.mode & 0o077) || stat.uid !== process.getuid())) throw Error('DENYLIST_REQUIRES_PRIVATE_PERMISSIONS');
  const terms = JSON.parse(fs.readFileSync(real, 'utf8'));
  if (!Array.isArray(terms) || !terms.length || terms.some(t => typeof t !== 'string' || t.length < 4 || t.includes('\n'))) throw Error('INVALID_PRIVATE_DENYLIST');
  return terms;
}

export function checkPrivacy({repo = process.cwd(), mode = 'worktree', directory, archive, denylist = process.env.REMOTE_SSH_PRIVATE_DENYLIST} = {}) {
  const privateTerms = loadPrivateTerms(denylist, repo);
  const git = args => execFileSync('git', args, {cwd: repo, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe']});
  let records = 0;
  const failures = [];
  const scan = (name, text) => { records++; for (const f of inspectText(text, {name, privateTerms})) failures.push({...f, record: records}); };
  const read = file => { if (fs.lstatSync(file).isSymbolicLink()) throw Error('SYMLINK_NOT_ALLOWED'); return fs.readFileSync(file, 'utf8'); };
  if (archive) {
    const entries = execFileSync('unzip', ['-Z1', archive], {encoding: 'utf8', maxBuffer: 1024 * 1024}).trim().split('\n');
    if (entries.length > 500) throw Error('ARCHIVE_TOO_LARGE');
    const seen = new Set(); let bytes = 0;
    for (const name of entries) {
      if (!name || name.startsWith('/') || name.includes('\\') || name.split('/').includes('..') || /[*?\[\]\r\0]/.test(name) || seen.has(name)) throw Error('INVALID_ARCHIVE_ENTRY');
      seen.add(name);
      if (name.endsWith('/')) continue;
      const text = execFileSync('unzip', ['-p', archive, name], {encoding: 'utf8', maxBuffer: 4 * 1024 * 1024});
      bytes += Buffer.byteLength(text); if (bytes > 16 * 1024 * 1024) throw Error('ARCHIVE_TOO_LARGE');
      scan(name, text);
    }
  } else if (directory) {
    const visit = (dir, prefix = '') => { for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
      const name = prefix + entry.name, file = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(file, name + '/'); else scan(name, read(file));
    }};
    visit(directory);
  } else if (mode === 'history') {
    const commits = git(['rev-list', '--all']).trim().split('\n').filter(Boolean), seen = new Set();
    if (!commits.length) throw Error('NO_HISTORY_TO_CHECK');
    scan('', git(['for-each-ref', '--format=%(refname) %(contents)']));
    for (const commit of commits) {
      scan('', git(['show', '-s', '--format=%an <%ae>%n%cn <%ce>%n%B', commit]));
      for (const row of git(['ls-tree', '-rz', commit]).split('\0').filter(Boolean)) {
        const [meta, name] = row.split('\t'), [mode, type, id] = meta.split(' '), identity = id + '\0' + name;
        if (seen.has(identity)) continue; seen.add(identity);
        if (type !== 'blob' || mode === '120000') throw Error('UNSUPPORTED_GIT_ENTRY');
        scan(name, git(['cat-file', 'blob', id]));
      }
    }
  } else if (mode === 'index') {
    for (const row of git(['ls-files', '--stage', '-z']).split('\0').filter(Boolean)) {
      const [meta, name] = row.split('\t'), [mode, id, stage] = meta.split(' ');
      if (stage !== '0' || mode === '120000' || mode === '160000') throw Error('UNSUPPORTED_INDEX_ENTRY');
      scan(name, git(['cat-file', 'blob', id]));
    }
  } else if (mode === 'worktree') {
    const files = new Set(git(['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean));
    for (const name of files) if (fs.existsSync(path.join(repo, name))) scan(name, read(path.join(repo, name)));
  } else throw Error('INVALID_MODE');
  if (!records) throw Error('NO_FILES_TO_CHECK');
  return {records, failures};
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2), options = {};
    for (let i = 0; i < args.length; i++) {
      if (['--history', '--index', '--worktree'].includes(args[i])) options.mode = args[i].slice(2);
      else if (['--directory', '--archive'].includes(args[i]) && args[i + 1]) options[args[i].slice(2)] = path.resolve(args[++i]);
      else throw Error('INVALID_ARGUMENT');
    }
    const result = checkPrivacy(options);
    if (result.failures.length) {
      for (const f of result.failures) console.error('PRIVACY_CHECK_FAILED rule=' + f.rule + ' record=' + f.record + ' line=' + f.line);
      process.exitCode = 1;
    } else console.log('PRIVACY_CHECK_OK records=' + result.records);
  } catch {
    console.error('PRIVACY_CHECK_ERROR: verify inputs, Git state and private denylist permissions. No source content was logged.');
    process.exitCode = 2;
  }
}
