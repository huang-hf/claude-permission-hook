"""Personal rules: edit this file to customize automatic approvals.

Two entry points are called by secure_handler.py (the core):
- approved_programs(command, cwd): approve a fully checked command, or return None.
- redirect_rules(command): add allowances for checked output targets.

The helpers and _command() below implement the supplied personal rule set.
scoped_policy.json remains optional scope data, not another code layer.
No shell commands or network calls are run by these rules.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit


def _literal(word):
    if getattr(word, 'parts', []):
        raise ValueError('shell expansion')
    raw = word.value
    quote = None
    escaped = False
    for char in raw:
        if escaped:
            escaped = False
            continue
        if char == '\\' and quote != "'":
            escaped = True
        elif char == quote:
            quote = None
        elif not quote and char in ('"', "'"):
            quote = char
        elif not quote and char in '$`*?[]{}~!()':
            raise ValueError('nonliteral word')
    result = shlex.split(raw)
    if len(result) != 1:
        raise ValueError('not one word')
    return result[0]


def _options(args, values=(), flags=()):
    """Strict option allowlist. Unknown/duplicate options fail closed."""
    opts, pos = {}, []
    i = 0
    while i < len(args):
        arg = args[i]
        key, sep, value = arg.partition('=')
        if key in flags and not sep:
            if key in opts:
                raise ValueError('duplicate option')
            opts[key] = True
        elif key in values:
            if key in opts:
                raise ValueError('duplicate option')
            if not sep:
                i += 1
                value = args[i]
            opts[key] = value
        elif arg.startswith('-'):
            raise ValueError('unknown option')
        else:
            pos.append(arg)
        i += 1
    return opts, pos


def _inside(value, root):
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    return resolved.is_relative_to(root.resolve())


def _tmp(value):
    return Path(value).is_absolute() and _inside(value, Path('/tmp')) and Path(value).resolve() != Path('/tmp').resolve()


def _path(value, cwd):
    protected = {'.git', '.codex', '.claude', '.ssh', '.aws', '.coffer',
                 '.git-credentials', '.npmrc', '.pypirc', '.pgpass'}
    return (bool(re.fullmatch(r'[\w /.-]+', value)) and _inside(value, cwd)
            and not any(part in protected or part == '.env' or part.startswith('.env.')
                        for part in Path(value).parts))


def _curl(args, policy):
    expanded = []
    for arg in args:
        if re.fullmatch(r'-[fLsSI]+', arg):
            expanded.extend('-' + c for c in arg[1:])
        else:
            expanded.append(arg)
    opts, pos = _options(expanded, ('-o', '--output', '--max-time', '--connect-timeout'),
                         ('-f', '-L', '-s', '-S', '-I', '--fail', '--location', '--silent', '--show-error', '--head'))
    if len(pos) != 1 or ('-o' in opts and '--output' in opts):
        return False
    url = urlsplit(pos[0])
    if (url.scheme != 'https' or url.username or url.password or url.fragment
            or any(c in url.path for c in '%{}[]\\')
            or any(part in ('.', '..') for part in url.path.split('/'))):
        return False
    allowed = False
    for endpoint in policy.get('http_read_endpoints', []):
        target = urlsplit(endpoint)
        if url.netloc == target.netloc and (url.path.startswith(target.path) if target.path.endswith('/') else url.path == target.path):
            allowed = True
    output = opts.get('-o', opts.get('--output'))
    return allowed and (output is None or _tmp(output))


def _kubectl(args, policy):
    opts, pos = _options(args, ('--context', '-n', '--namespace', '-o', '--output', '-l', '--selector', '--timeout', '--request-timeout'),
                         ('-A', '--all-namespaces'))
    if opts.get('--context') not in policy.get('kube_contexts', []):
        return False
    if '-o' in opts and '--output' in opts:
        return False
    output = opts.get('-o', opts.get('--output', ''))
    if output and output not in ('json', 'yaml', 'wide', 'name') and not output.startswith(('jsonpath=', 'custom-columns=')):
        return False
    if pos[:2] == ['rollout', 'status']:
        resources = pos[2:]
        allowed = {'deployment', 'deployments', 'statefulset', 'statefulsets', 'daemonset', 'daemonsets'}
    elif pos[:1] == ['get']:
        resources = pos[1:]
        allowed = {'pod', 'pods', 'po', 'deployment', 'deployments', 'deploy', 'replicaset', 'replicasets', 'rs',
                   'statefulset', 'statefulsets', 'daemonset', 'daemonsets', 'service', 'services', 'svc',
                   'event', 'events', 'node', 'nodes', 'namespace', 'namespaces', 'job', 'jobs'}
    else:
        return False
    if not resources or resources[0].split('/')[0] not in allowed:
        return False
    # Resource/name forms must each name an allowed resource; plain names cannot
    # introduce another resource type (comma-separated resources are not supported).
    return all(',' not in token and (token.split('/')[0] in allowed if '/' in token else bool(re.fullmatch(r'[\w.-]+', token)))
               for token in resources)


def _aws(args, policy):
    if args[:2] != ['ecr', 'describe-images']:
        return False
    opts, pos = _options(args[2:], ('--region', '--repository-name', '--image-ids', '--query', '--output', '--max-items', '--next-token'))
    return not pos and opts.get('--region') in policy.get('aws_regions', []) and opts.get('--repository-name') in policy.get('ecr_repositories', []) and opts.get('--output', 'json') in ('json', 'text', 'table')


def _coffer(args, policy):
    if not args or args[0] not in ('check', 'run'):
        return False
    if args[0] == 'check':
        opts, pos = _options(args[1:], ('--ns',), ('--global', '--json'))
        return not pos and opts.get('--global') and opts.get('--json') and opts.get('--ns') in policy.get('coffer_namespaces', [])
    i = 1
    while i < len(args) and args[i].startswith('-'):
        if args[i] == '--ns':
            i += 2
        else:
            i += 1
    opts, pos = _options(args[1:i], ('--ns',), ('--global',))
    if pos or not opts.get('--global') or opts.get('--ns') not in policy.get('coffer_namespaces', []):
        return False
    inner = args[i:]
    if not inner:
        return False
    if inner[0] == 'kubectl':
        return _kubectl(inner[1:], policy)
    return inner[0] == 'aws' and _aws(inner[1:], policy)


def _git(args, cwd, policy):
    if not args:
        return False
    if args[0] == 'add':
        opts, pos = _options(args[1:], flags=('-A', '--all', '-u', '--update'))
        return bool(pos or opts) and all(_path(x, cwd) and not x.startswith('-') for x in pos)
    if args[0] == 'commit':
        opts, pos = _options(args[1:], ('-m', '--message'), ('-a', '--all', '-q', '--quiet'))
        return not pos and bool(opts.get('-m') or opts.get('--message')) and not ('-m' in opts and '--message' in opts)
    if args[0] == 'clone':
        return len(args) == 3 and args[1] in policy.get('clone_sources', []) and _path(args[2], cwd) and not args[2].startswith('-')
    return False


def _python(args, cwd):
    if args[:2] == ['-m', 'http.server']:
        opts, pos = _options(args[2:], ('--bind', '-b', '--directory', '-d'))
        if ('--bind' in opts and '-b' in opts) or ('--directory' in opts and '-d' in opts):
            return False
        bind = opts.get('--bind', opts.get('-b'))
        directory = opts.get('--directory', opts.get('-d', '.'))
        return len(pos) <= 1 and (not pos or pos[0].isdigit() and 0 < int(pos[0]) < 65536) and bind in ('127.0.0.1', '::1') and _path(directory, cwd)
    if args[:2] == ['-m', 'unittest']:
        opts, pos = _options(args[2:], ('-s', '--start-directory', '-t', '--top-level-directory', '-p', '--pattern', '-k'),
                             ('-q', '--quiet', '-v', '--verbose', '-b', '--buffer', '-f', '--failfast', '-c', '--catch'))
        paths = [v for k, v in opts.items() if k in ('-s', '--start-directory', '-t', '--top-level-directory')]
        return all(_path(v, cwd) for v in paths) and all(re.fullmatch(r'[\w.]+', v) for v in pos)
    return False


def _command(words, cwd, policy):
    tool, args = words[0], words[1:]
    if tool == 'curl':
        return _curl(args, policy)
    if tool in ('lark-cli', 'gh'):
        return True
    if tool == 'kubectl':
        return _kubectl(args, policy)
    if tool == 'coffer':
        return _coffer(args, policy)
    if tool == 'git':
        return _git(args, cwd, policy)
    if tool in policy.get('python_executables', []):
        return _python(args, cwd)
    if tool == 'code':
        opts, pos = _options(args, flags=('--reuse-window', '--wait'))
        return bool(pos) and all(_path(v, cwd) for v in pos)
    return False


def approved_programs(command: str, cwd: str) -> set[str] | None:
    """Approve static lark-cli/gh commands globally; other programs require scopes."""
    try:
        from dippy.vendor.parable import parse
        # Global personal allowances do not require project scope data.
        policy = {}
        trusted = False
        directory = Path(cwd).resolve()
        try:
            config = Path(os.getenv('SECURE_HANDLER_POLICY_PATH') or Path(__file__).with_name('scoped_policy.json'))
            candidate = json.loads(config.read_text())
            if not isinstance(candidate, dict) or any(
                    not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value)
                    for value in candidate.values()):
                raise ValueError('invalid scope data')
            roots = [Path(root).expanduser() for root in candidate.get('trusted_roots', [])]
            if any(not root.is_absolute() for root in roots):
                raise ValueError('relative trusted root')
            trusted = Path(cwd).is_absolute() and any(directory.is_relative_to(root.resolve()) for root in roots)
            policy = candidate
        except (OSError, ValueError, TypeError):
            pass
        pending = list(parse(command))
        programs = set()
        while pending:
            node = pending.pop()
            kind = getattr(node, 'kind', '')
            if kind == 'list':
                pending.extend(node.parts)
                continue
            if kind == 'operator' and node.op in ('&&', ';', '\n'):
                continue
            if kind != 'command':
                return None
            words = [_literal(word) for word in node.words]
            if not words or (words[0] not in ('lark-cli', 'gh') and not trusted):
                return None
            if not _command(words, directory, policy):
                return None
            for redir in node.redirects:
                if redir.kind != 'redirect' or redir.op not in ('>', '>>', '&>', '&>>', '2>', '2>>') or not _tmp(_literal(redir.target)):
                    return None
            programs.add(words[0])
        return programs or None
    except Exception:
        # No opinion if parser/config is unavailable or the syntax is unsupported.
        return None


def redirect_rules(command: str):
    """Permit literal output paths resolving inside /tmp, including overwrites.

    Add exact per-target rules to dippy rather than approving the command here.
    The AST analyzer still checks every command, substitution and other redirect.
    """
    from dippy.core.config import Rule
    from dippy.vendor.parable import parse

    root = Path('/tmp').resolve()
    pending = list(parse(command))
    rules = []
    seen = set()
    while pending:
        node = pending.pop()
        if isinstance(node, (list, tuple)):
            pending.extend(node)
            continue
        if not hasattr(node, '__dict__') or id(node) in seen:
            continue
        seen.add(id(node))
        pending.extend(vars(node).values())
        if getattr(node, 'kind', '') != 'redirect' or getattr(node, 'op', '') not in (
                '>', '>>', '&>', '&>>', '2>', '2>>'):
            continue
        target = getattr(getattr(node, 'target', None), 'value', '')
        if len(target) >= 2 and target[0] == target[-1] and target[0] in ('"', "'"):
            target = target[1:-1]
        # Dynamic/escaped/glob targets are left to the existing analyzer.
        if not target.startswith(('/tmp/', str(root) + '/')) or not re.fullmatch(
                r'[\w /.-]+', target):
            continue
        resolved = Path(target).resolve()
        if resolved != root and resolved.is_relative_to(root):
            rules.append(Rule('allow', target, source='secure_handler:tmp_redirect'))
    return rules
