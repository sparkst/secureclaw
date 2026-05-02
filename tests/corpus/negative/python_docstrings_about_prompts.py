"""Module: prompt utilities.

This module discusses how AI assistants interpret a system prompt at
runtime. We document the contract between the system prompt and user
input. The library does not actually issue any directives to the AI; it
only inspects strings that look like prompt injection patterns.
"""


def describe_prompt(text: str) -> str:
    """Return a brief description of how a prompt is structured.

    The returned string is for documentation purposes only.
    """
    return f"This prompt has {len(text)} characters."
