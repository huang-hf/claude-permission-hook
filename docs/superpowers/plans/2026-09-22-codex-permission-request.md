# Codex PermissionRequest Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Share the existing permission judge between Claude Code and Codex, and publish the tested integration to this repository.

**Architecture:** Add a Codex adapter to secure_handler.py, selected with --agent codex. Accept only canonical Bash PermissionRequest events with valid command/cwd strings. Emit Codex's decision.behavior=allow only for an explicit allow verdict; all other outcomes defer to normal approval. Do not register PreToolUse: Codex cannot turn its ask result into a prompt. Do not parse apply_patch as a shell command.

**Tech Stack:** Python 3.10+, unittest, Codex command hooks.

## Task 1: Adapter and contract tests

- [x] Add tests/test_codex.py: subprocess approval schema with real dippy, redline deferral and audit, malformed/unsupported events, both agent argument forms, unexpected decisions and backend errors.
- [x] Run `/usr/local/bin/python3.12 -m unittest tests.test_codex -v` and verify approval fails before implementation.
- [x] Add parse_codex and emit_codex to secure_handler.py and register the adapter. Reuse judge and audit without changing Claude behavior.
- [x] Run the new tests and the full unittest discovery suite.

## Task 2: Installation and documentation

- [x] Add codex.hooks.json.template for synchronous Bash PermissionRequest using the shared installed script and a pinned Python path.
- [x] Document template merging, hook trust, environment inheritance, audit location, and limitations (already-allowed calls, PreToolUse ask, apply_patch/MCP).
- [x] Review the diff and verify JSON and CLI configuration compatibility.
- [x] Install the tested shared script and merge the Codex hook without overwriting existing hooks, backing up changed files first. Runtime trust remains a user action through /hooks.

## Task 3: Publish

- [ ] Commit and push the reviewed changes to the supplied repository without force, then confirm the remote commit matches (release step after this document is committed).

## Validation boundaries

Tests use local stubs or disable remote backends; no real model credentials are needed. Hook contract tests establish emitted decisions, not a live desktop approval round trip. A trusted/reloaded Codex hook is required before real use. The installed CLI was observed as 0.155.1 with hooks enabled; other clients must support PermissionRequest.

## Verified results

- New contract tests failed before adapter implementation, then all six passed.
- Full suite: 126 tests passed; existing HTTP fixtures emit ResourceWarning for unclosed sockets.
- Independent implementation review found no blocking issues; clarified credential fallback wording.
- JSON template parsed, diff whitespace checks passed, and installed hook command was invoked directly: git status allowed, rm -rf build deferred. Neither sample shell command was executed.
- Shared installed script matches repository bytes. Existing installed script backed up before replacement.
- Live client approval round trip remains unverified until the user trusts the hook through /hooks.
