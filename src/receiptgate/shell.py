"""A deliberately small shell grammar, rejecting expansion and hidden execution.

This is a policy aid, not a shell interpreter or sandbox. Quoted operators stay data.
"""

import shlex


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
        executable = part[0].split("/")[-1]
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
            ]
            or executable == "env"
            and len(part) > 1
        ):
            raise ShellError("indirect execution is unsupported; use a direct command")
        if executable in ["npm", "kubectl", "make"] and len(part) > 1 and part[1].startswith("-"):
            raise ShellError("leading command options require manual review")
    return words


def segments(words: list[str]) -> list[list[str]]:
    result: list[list[str]] = [[]]
    for word in words:
        if word and all(c in ";&|<>" for c in word):
            result.append([])
        else:
            result[-1].append(word)
    return [part for part in result if part]
