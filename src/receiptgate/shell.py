"""A deliberately small shell grammar, rejecting expansion and hidden execution.

This is a policy aid, not a shell interpreter or sandbox. Operator-only quoted arguments may be conservatively rejected.
"""

import shlex
from pathlib import Path


class ShellError(ValueError):
    pass


def tokens(command: str) -> list[str]:
    if not command.strip() or "\x00" in command or "\n" in command:
        raise ShellError("empty, multiline or NUL command is unsupported")
    # Reject expansion even in quotes: false positives are safer than hidden calls.
    if any(s in command for s in ["$", "`", "\\", "<<"]):
        raise ShellError("expansion, substitution, heredocs and compound syntax are unsupported")
    quote = None
    for char in command:
        if char in ["'", '"']:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        elif quote is None and char in "(){}*?[~":
            raise ShellError("compound shell syntax is unsupported")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        words = list(lexer)
    except ValueError as exc:
        raise ShellError("invalid shell quoting") from exc
    for part in segments(words):
        validate_exec(part)
    return words


def segments(words: list[str]) -> list[list[str]]:
    result: list[list[str]] = [[]]
    for word in words:
        if word and all(c in ";&|<>" for c in word):
            result.append([])
        else:
            result[-1].append(word)
    return [part for part in result if part]


def executable_name(value: str) -> str:
    return Path(value).name.lower().removesuffix(".exe")


def validate_exec(part: list[str]) -> None:
    if not part or not part[0] or any("\x00" in arg for arg in part):
        raise ShellError("empty executable or NUL argument is unsupported")
    if Path(part[0]).suffix.lower() in [".bat", ".cmd"]:
        raise ShellError("batch files require a shell and manual review")
    executable = executable_name(part[0])
    if (
        "=" in part[0]
        or executable
        in [
            "if",
            "then",
            "fi",
            "for",
            "while",
            "until",
            "do",
            "done",
            "case",
            "esac",
            "function",
            "select",
            "!",
            "eval",
            "source",
            ".",
            "bash",
            "sh",
            "zsh",
            "fish",
            "sudo",
            "command",
            "exec",
            "xargs",
            "find",
            "nice",
            "nohup",
            "timeout",
            "time",
            "setsid",
            "chrt",
            "ionice",
            "stdbuf",
            "unbuffer",
            "watch",
            "parallel",
            "doas",
            "busybox",
            "cmd",
            "powershell",
            "pwsh",
        ]
        or executable == "env"
        and len(part) > 1
    ):
        raise ShellError("indirect execution is unsupported; use a direct command")
    if executable in ["npm", "kubectl", "make"] and len(part) > 1 and part[1].startswith("-"):
        raise ShellError("leading command options require manual review")
