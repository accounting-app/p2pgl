#!/bin/bash
# PreToolUse(Bash): only the maintainer stages, commits or pushes in this repo
# (CLAUDE.md, "Working agreement"; docs/build-log/004-no-python).
#
# Denies a command that would run `git add`, `stage`, `mv`, `rm`, `commit` or
# `push`: within one simple command, the word `git` (or a path ending in
# `/git`, any case) and then, after git's own options (`-C dir`, `-c k=v`,
# `--git-dir …`), one of those as git's subcommand. The command is read the way
# bash reads it, in one pass:
#   - simple commands end at `;` `&` `|` `(` `)` and a newline, so
#     `cd x && git add y`, `(cd x); git push`, `if …; then git add …`,
#     `sudo git commit`, `xargs git add` and `env A=1 git push` are caught;
#   - quotes and backslashes join a word, as in bash: `g\it`, `'g'it`,
#     `git co""mmit` and `git 'commit'` are `git commit`; a line ending in `\`
#     continues;
#   - `$( … )` and backticks are commands of their own, wherever they appear —
#     in double quotes, as an option's value (`git -C "$(pwd)" commit`), in an
#     unquoted heredoc body;
#   - a quoted string is data, unless it follows a shell, `eval`, `trap`,
#     `su`, `watch` or `env -S` in the same command (`bash -ce 'git commit'`),
#     where it is code;
#   - a heredoc body is data (only its `$( … )` runs, and only when its
#     delimiter is unquoted); a `#` at the start of a word starts a comment.
# So `grep 'git add'`, `echo "git add later"`, `git stash push`, `git remote
# add` and a heredoc that mentions `git commit` all pass.
#
# Not caught, as no reading of the text can catch them — the permission
# prompts are the backstop: a git hidden in a variable (`$G commit`), an alias
# (`git -c alias.x=commit x`), a program fed to a shell on stdin (`echo … |
# bash`), `$'…'` escapes. Input it cannot read is refused, never waved
# through; so is a command whose quotes do not close (it would not run).
#
# Its cases are guard_git_cases.jsonl, run by test_guard_git.sh (in the gate,
# and as xtask's `guard` test, which the revert checks use).

# A refusal, written without jq: it must work when jq is the problem.
deny() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$1"
  exit 0
}
unreadable() {
  deny "the git guard could not read this command, so it is refused (.claude/hooks/guard_git.sh): $1"
}

command -v jq >/dev/null 2>&1 || unreadable "jq is not installed"
command -v awk >/dev/null 2>&1 || unreadable "awk is not installed"
input=$(cat) || unreadable "no input"
command=$(printf '%s' "$input" | jq -er '.tool_input.command // ""' 2>/dev/null) || unreadable "the input is not the JSON a hook gets"

# LC_ALL=C: bytes, not characters. In a UTF-8 locale macOS awk fails on a
# multi-byte character (an em dash), and no byte of one is a quote or a
# separator, so reading bytes changes no verdict.
verdict=$(printf '%s\n' "$command" | LC_ALL=C awk '
BEGIN {
  split("add stage mv rm commit push", list, " "); for (k in list) BLOCKED[list[k]] = 1
  split("-c -C --git-dir --work-tree --namespace --super-prefix --config-env", list, " "); for (k in list) VALUED[list[k]] = 1
  split("sh bash zsh dash ksh fish eval trap su watch", list, " "); for (k in list) SHELLS[list[k]] = 1
  mode = "n"; d = 0; first = 1; npending = 0; cont = 0; blocked = 0
  word = ""; wlen = 0; expect = 0; shellish = 0; envseen = 0; codeq = ""; paren = 0; kind = ""
}

# A character into the current word. Long words keep only their tail: no word
# that long is `git` or a subcommand, and a path ending in /git still shows.
function addc(c) {
  word = word c; wlen++
  if (wlen > 256) { word = substr(word, wlen - 31); wlen = 32 }
}

function endword(    lw, base) {
  if (wlen == 0) return
  word_raw = word; lw = tolower(word); word = ""; wlen = 0
  if (expect == 2) { expect = 1; return }        # the value of a git option
  if (expect == 1) {
    if (lw ~ /^-/) { if ((lw in VALUED) && lw !~ /=/) expect = 2; return }
    if (lw in BLOCKED) { blocked = 1; print "BLOCK " lw; exit }
    expect = 0
  }
  if (lw == "git" || lw ~ /\/git$/) { expect = 1; return }
  base = lw; sub(/.*\//, "", base)
  if (base in SHELLS) shellish = 1
  if (base == "env") envseen = 1
  if (envseen && (word_raw == "-S" || word_raw ~ /^--split-string/)) shellish = 1
}

# The end of a simple command. Inside a quoted program (`bash -c '…'`) the
# program goes on: its commands end, the quoted text does not.
function endseg() { endword(); expect = 0; if (codeq == "") { shellish = 0; envseen = 0 } }

# `$(` or a backtick: a command of its own; its text becomes one character of
# the word around it.
function push(k) {
  d++
  S_mode[d] = mode; S_word[d] = word; S_wlen[d] = wlen; S_expect[d] = expect
  S_shell[d] = shellish; S_env[d] = envseen; S_codeq[d] = codeq; S_paren[d] = paren; S_kind[d] = kind
  mode = "n"; word = ""; wlen = 0; expect = 0; shellish = 0; envseen = 0; codeq = ""; paren = 0; kind = k
}
function pop() {
  endseg()
  mode = S_mode[d]; word = S_word[d]; wlen = S_wlen[d]; expect = S_expect[d]
  shellish = S_shell[d]; envseen = S_env[d]; codeq = S_codeq[d]; paren = S_paren[d]; kind = S_kind[d]
  d--
  addc("x")
}

# A heredoc opener at line[i] ("<<"): note its delimiter; return the index of
# its last character.
function heredoc(line, i, len,    j, c, raw, delim, strip) {
  j = i + 2; strip = 0
  if (substr(line, j, 1) == "-") { strip = 1; j++ }
  while (j <= len && (substr(line, j, 1) == " " || substr(line, j, 1) == "\t")) j++
  raw = ""
  while (j <= len) {
    c = substr(line, j, 1)
    if (c ~ /[ \t;&|<>()]/) break
    raw = raw c; j++
  }
  delim = raw; gsub(/["\047\\]/, "", delim)
  if (delim == "") return i + 1
  npending++
  P_delim[npending] = delim; P_quoted[npending] = (raw != delim); P_strip[npending] = strip
  return j - 1
}

{
  line = $0; len = length(line)

  # A heredoc body line: data, unless its delimiter is unquoted, where only
  # `$( … )` and backticks in it run.
  if (first <= npending && mode == "n" && !cont) {
    probe = line
    if (P_strip[first]) sub(/^\t+/, "", probe)
    if (probe == P_delim[first]) { first++; next }
    if (P_quoted[first]) next
    mode = "hd"
  }
  cont = 0
  # One character per element: indexing the line itself costs its length
  # on every read in some awks, which made a long line quadratic.
  len = split(line, ch, "")

  for (i = 1; i <= len; i++) {
    c = ch[i]
    if (mode == "hd") {
      if (c == "\\") { i++; continue }
      if (c == "$" && ch[i + 1] == "(") { i++; push("("); continue }
      if (c == "`") { push("`"); continue }
      continue
    }
    if (mode == "sq") {                          # data: one word, its blanks joined
      if (c == "\047") { mode = "n"; continue }
      addc(c ~ /[ \t;&|()`]/ ? "_" : c)
      continue
    }
    if (mode == "dq") {
      if (c == "\"") { mode = "n"; continue }
      if (c == "\\") { if (i == len) { cont = 1; break }; i++; addc(ch[i]); continue }
      if (c == "$" && ch[i + 1] == "(") { i++; push("("); continue }
      if (c == "`") { push("`"); continue }
      addc(c)
      continue
    }
    # Unquoted (mode "n"; also the text of a quoted program, closed by codeq).
    if (c == "\\") { if (i == len) { cont = 1; break }; i++; addc(ch[i]); continue }
    if (codeq != "" && c == codeq) { codeq = ""; continue }
    if (c == "#" && wlen == 0 && codeq == "") break
    if (c == " " || c == "\t" || c == "\r") { endword(); continue }
    # A quoted string after a shell, eval, trap, su, watch or `env -S` is a
    # program: read on (`env -S'…'` too, the quote right after the flag).
    if ((c == "\047" || c == "\"") && codeq == "" && (shellish || (envseen && word == "-S"))) {
      if (wlen > 0) endword()
      codeq = c; continue
    }
    if (c == "\047") { mode = "sq"; continue }
    if (c == "\"") { mode = "dq"; continue }
    if (c == "`") { if (d > 0 && kind == "`") pop(); else push("`"); continue }
    if (c == "$" && ch[i + 1] == "(") { i++; push("("); continue }
    if (c == "$" && ch[i + 1] == "\047") { i++; mode = "sq"; continue }
    if (c == "<" && ch[i + 1] == "<") {
      if (ch[i + 2] == "<") { i += 2; continue }   # <<< here-string
      endword(); i = heredoc(line, i, len); continue
    }
    if (c == "(") { paren++; endseg(); continue }
    if (c == ")") {
      if (paren > 0) { paren--; endseg(); continue }
      if (d > 0 && kind == "(") { pop(); continue }
      endseg(); continue
    }
    if (c == ";" || c == "&" || c == "|") { endseg(); continue }
    addc(c)
  }

  if (mode == "hd") { mode = "n"; next }
  if (cont) next
  if (mode == "n") endseg()
  else if (mode == "sq") addc("_")
  else if (mode == "dq") addc(" ")
}

END {
  if (blocked) exit
  if (mode == "n" && !cont) endseg()
  if (blocked) exit
  # A trailing `\` (bash would wait for more) counts as unclosed, as does an
  # open quote or substitution.
  if (cont || mode != "n" || d > 0 || codeq != "") { print "UNCLOSED"; exit }
  print "OK"
}') || unreadable "awk failed"

case "$verdict" in
  OK) exit 0 ;;
  "BLOCK "*)
    deny "\`git ${verdict#BLOCK }\` is the maintainer's step in this repo: only they stage, move, remove, commit and push in git. Stop and tell them the work is ready to commit (CLAUDE.md, Working agreement)." ;;
  UNCLOSED) unreadable "its quotes or substitutions do not close" ;;
  *) unreadable "unexpected verdict" ;;
esac
