#!/usr/bin/env python3
"""PreToolUse(Bash): only the maintainer stages, commits or pushes in this repo.

The maintainer reviews, stages and commits every unit of work themselves
(CLAUDE.md, "Working agreement"). This denies `git add` (and its alias
`git stage`), `git mv` and `git rm` (both stage their change), `git commit`
and `git push` wherever they appear as a command: at the start, after `;`,
`&&`, `||`, `|`, a newline, inside `( … )`, `$( … )` or backticks, after
`VAR=value` or `env`, and with git options such as `-C <dir>`. Every other git
command passes.

Text that is not a command is ignored: quoted strings (a commit message, a
`python3 -c '…'` program, a `grep 'git add'` pattern) and heredoc bodies (a
file being written with `cat <<'EOF'`). The first version split on `|`, `(`
and backticks even inside quotes and heredocs, and refused commands that only
mentioned `git add` in the text they wrote.
"""
import json
import re
import shlex
import sys

# Options of `git` itself that take a separate value.
GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
BLOCKED = {"add", "stage", "mv", "rm", "commit", "push"}
# Tokens after which the next word is in command position.
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "\n", "$(", "`", "{", "}", "!"}
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def strip_heredoc_bodies(command: str) -> str:
    """Drop the lines of every heredoc body, keeping the line that opens it."""
    kept, pending = [], []
    for line in command.split("\n"):
        if pending:
            if line.strip() == pending[0]:
                pending.pop(0)
            continue
        kept.append(line)
        pending.extend(match.group(2) for match in HEREDOC.finditer(line))
    return "\n".join(kept)


def tokens_of(command: str):
    """Shell words and separators, with quotes honoured."""
    # `$(` and backticks open a command; make them stand-alone separators.
    command = command.replace("$(", " $( ").replace("`", " ` ")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    out = []
    for token in lexer:
        # A newline outside quotes separates commands; keep it as a token.
        parts = token.split("\n") if "\n" in token and not token.strip() == "" else [token]
        for index, part in enumerate(parts):
            if index:
                out.append("\n")
            if part:
                out.append(part)
    return out


def blocked_subcommand(command: str):
    try:
        tokens = tokens_of(strip_heredoc_bodies(command))
    except ValueError:
        # Unbalanced quotes: fall back to plain words, erring towards refusal.
        tokens = re.split(r"\s+|(?=[;&|()`])", command)
    at_command = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in SEPARATORS:
            at_command = True
            index += 1
            continue
        if at_command and (token == "env" or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token)):
            index += 1
            continue
        if at_command and token == "git":
            position = index + 1
            while position < len(tokens) and tokens[position].startswith("-"):
                position += 2 if tokens[position] in GIT_VALUE_OPTIONS else 1
            if position < len(tokens) and tokens[position] in BLOCKED:
                return tokens[position]
        at_command = False
        index += 1
    return None


def main():
    command = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    subcommand = blocked_subcommand(command)
    if subcommand:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"`git {subcommand}` is the maintainer's step in this repo: only they stage, "
                    "move, remove, commit and push in git. Stop and tell them the work is ready "
                    "to commit (CLAUDE.md, Working agreement)."
                ),
            }
        }))


if __name__ == "__main__":
    main()
