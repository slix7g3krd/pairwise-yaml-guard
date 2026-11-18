"""Hardening helpers for untrusted YAML configuration.

The functions in this module are deliberately defensive: every parser or
composer failure (including ``RecursionError`` from deeply nested input) is
treated as unsafe and fails closed.  The companion :func:`safe_load` /
:func:`safe_load_all` entry points combine the individual checks into a full
validating loader for the configuration centre.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

__all__ = [
    "YamlGuardError",
    "is_safe_loader",
    "has_python_tag",
    "has_duplicate_keys",
    "depth_ok",
    "alias_count",
    "sanitize_comment",
    "is_single_document",
    "safe_load",
    "safe_load_all",
    "MAX_INPUT_CHARS",
    "MAX_DEPTH",
    "MAX_ALIASES",
    "MAX_SCALAR_CHARS",
    "MAX_ALIAS_EXPANSIONS",
]

TAG_PREFIX = "tag:yaml.org,2002:"
TAG_PYTHON = TAG_PREFIX + "python"
TAG_MERGE = TAG_PREFIX + "merge"
TAG_BOOL = TAG_PREFIX + "bool"
TAG_NULL = TAG_PREFIX + "null"
TAG_STR = TAG_PREFIX + "str"

#: Hard limits applied by :func:`safe_load` / :func:`safe_load_all`.
MAX_INPUT_CHARS = 1_000_000
MAX_DEPTH = 50
MAX_ALIASES = 100
MAX_SCALAR_CHARS = 100_000
MAX_ALIAS_EXPANSIONS = 2_000

#: Parser-protection bound on flow-collection nesting (``[``/``{``).  PyYAML's
#: own composer hits ``RecursionError`` around 500 levels, so no parseable
#: document can approach this; the check exists only to reject pathological
#: input (where PyYAML degrades quadratically) before any parsing happens.
MAX_FLOW_NESTING = 400

#: Loader names that are safe: they never instantiate arbitrary Python objects.
_SAFE_LOADER_NAMES = frozenset({"SafeLoader", "CSafeLoader"})

#: Only the implicitly resolved true/false spellings are accepted.  YAML 1.1
#: also resolves ``yes/no/on/off`` to booleans, which is a classic way to
#: smuggle a string that later code treats as a boolean.
_STRICT_BOOLS = frozenset({"true", "false"})

_TRUE_WORDS = frozenset({"true", "yes", "on"})

# A tag is unsafe when it names the Python object namespace or when it is a
# custom/local tag.  ``!`` and ``?`` alone are the standard non-specific tags
# and do not carry a constructor; PyYAML leaves them unresolved.
_PYTHON_TAG_RE = re.compile(r"!!python|tag:yaml\.org,2002:python")


class YamlGuardError(ValueError):
    """Raised when a YAML document violates the configuration guard policy."""


# ---------------------------------------------------------------------------
# Loader selection
# ---------------------------------------------------------------------------

def is_safe_loader(loader: Any) -> bool:
    """Return ``True`` only for a loader that cannot construct arbitrary objects.

    Accepts either a loader name (``"SafeLoader"``, ``"yaml.CSafeLoader"``) or
    the loader class itself.  ``Loader``, ``FullLoader``, ``UnsafeLoader`` and
    subclasses thereof are rejected.  Empty/invalid values are rejected.
    """
    if isinstance(loader, str):
        name = loader.strip().rsplit(".", 1)[-1]
        return name in _SAFE_LOADER_NAMES

    if isinstance(loader, type):
        safe_classes = {
            getattr(yaml, "SafeLoader", None),
            getattr(yaml, "CSafeLoader", None),
        }
        safe_classes.discard(None)
        if loader in safe_classes:
            return True
        try:
            return issubclass(loader, yaml.SafeLoader)
        except TypeError:  # pragma: no cover - defensive
            return False

    return False


# ---------------------------------------------------------------------------
# Tag policy
# ---------------------------------------------------------------------------

def _is_unsafe_tag(tag: str) -> bool:
    if tag in ("!", "?"):
        return False
    if tag.startswith(TAG_PYTHON):
        return True
    return not tag.startswith(TAG_PREFIX)


def has_python_tag(text: Any) -> bool:
    """Return ``True`` if *text* uses an unsafe tag.

    Python tags (``!!python/object``, ``!!python/object/apply``, verbatim or
    ``%TAG``-declared equivalents) and custom/local tags (``!Foo``) are all
    rejected.  Standard YAML tags such as ``!!str`` are accepted.

    Detection uses the parser so tags appearing inside quoted scalars or
    comments are not reported.  If the document cannot be parsed, a textual
    fallback looks for Python tag spellings and fails closed only when one is
    present -- malformed documents are rejected by the document-level checks.
    """
    if not isinstance(text, str):
        return True
    if _flow_nesting_exceeded(text, MAX_FLOW_NESTING):
        # Pathological input that PyYAML cannot compose in reasonable time;
        # fail closed without handing it to the parser.
        return True
    try:
        for event in yaml.parse(text):
            tag = getattr(event, "tag", None)
            if tag and _is_unsafe_tag(tag):
                return True
        return False
    except Exception:
        return bool(_PYTHON_TAG_RE.search(text))


# ---------------------------------------------------------------------------
# Duplicate keys and merge-key overrides
# ---------------------------------------------------------------------------

def _canonical_key(node: Node) -> tuple:
    """A hashable identity for a mapping key, respecting the resolved type.

    Scalar keys are canonicalised through SafeLoader so that, for example,
    ``yes`` and ``true`` (both booleans) collide, while ``1`` (int) and
    ``"1"`` (str) do not.
    """
    if not isinstance(node, ScalarNode):
        # Complex keys are rare; compare by identity (aliases share nodes).
        return ("complex", id(node))

    tag = node.tag
    value = node.value
    if tag == TAG_STR:
        return (TAG_STR, value)
    try:
        resolved = yaml.safe_load(value)
    except Exception:
        return (tag, value)
    if isinstance(resolved, (dict, list)):
        return (tag, value)
    return (tag, type(resolved).__name__, resolved)


def _merge_sources(value: Node):
    """Return the mappings contributed by a ``<<`` merge value.

    Returns ``None`` when the merge value is invalid (neither a mapping nor a
    sequence of mappings); the caller treats that as unsafe.
    """
    if isinstance(value, MappingNode):
        return [value]
    if isinstance(value, SequenceNode):
        sources = []
        for item in value.value:
            if not isinstance(item, MappingNode):
                return None
            sources.append(item)
        return sources
    return None


def _mapping_has_duplicate(node: MappingNode) -> bool:
    explicit: set = set()
    merged: set = set()
    seen_merge = False

    for key, value in node.value:
        if isinstance(key, ScalarNode) and key.tag == TAG_MERGE:
            if seen_merge:
                return True
            seen_merge = True
            sources = _merge_sources(value)
            if sources is None:
                return True
            for source in sources:
                for source_key, _ in source.value:
                    canonical = _canonical_key(source_key)
                    # A merge must never override an explicit key, and two
                    # merge sources must not disagree about the same key.
                    if canonical in explicit or canonical in merged:
                        return True
                    merged.add(canonical)
            continue

        canonical = _canonical_key(key)
        if canonical in explicit:
            return True
        explicit.add(canonical)

    return False


def _node_has_duplicate_keys(node: Node, visited: set) -> bool:
    """Iteratively scan a node tree for duplicate keys.

    Iterative on purpose: recursion here would let deeply nested input exhaust
    the interpreter stack before the depth guard sees it.
    """
    pending = [node]
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))

        if isinstance(current, MappingNode):
            if _mapping_has_duplicate(current):
                return True
            pending.extend(child for pair in current.value for child in pair)
        elif isinstance(current, SequenceNode):
            pending.extend(current.value)

    return False


def _documents_have_duplicate_keys(documents) -> bool:
    visited: set = set()
    return any(_node_has_duplicate_keys(doc, visited) for doc in documents)


def has_duplicate_keys(text: Any) -> bool:
    """Return ``True`` if any mapping has a duplicate or merge-overridden key.

    Duplicates are detected across all documents and all nesting levels.
    Duplicate ``<<`` keys, a merge that overrides an explicit key, and
    conflicting merge sources are rejected.  Unparseable input fails closed.
    """
    if not isinstance(text, str):
        return True
    if _flow_nesting_exceeded(text, MAX_FLOW_NESTING):
        return True
    try:
        documents = list(yaml.compose_all(text))
    except Exception:
        return True
    return _documents_have_duplicate_keys(documents)


# ---------------------------------------------------------------------------
# Depth limiting
# ---------------------------------------------------------------------------

def depth_ok(depth: Any, limit: Any) -> bool:
    """Return ``True`` when *depth* does not exceed *limit*.

    Both arguments must be real numbers (booleans and strings are rejected)
    and *limit* must be non-negative.
    """
    if isinstance(depth, bool) or isinstance(limit, bool):
        return False
    if not isinstance(depth, (int, float)) or not isinstance(limit, (int, float)):
        return False
    if limit < 0:
        return False
    return depth <= limit


# ---------------------------------------------------------------------------
# Alias counting / expansion limiting
# ---------------------------------------------------------------------------

_BLOCK_HEADER_RE = re.compile(r"(?:^|[\s:,\-])[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*$")
_ALIAS_RE = re.compile(r"(?:^|[\s\[\]{},])\*([A-Za-z0-9_.\-]+)", re.MULTILINE)


def _strip_line_comment(line: str, in_single: bool, in_double: bool):
    """Strip a trailing comment, honouring quotes and multi-line scalars."""
    i = 0
    length = len(line)
    while i < length:
        char = line[i]
        if in_single:
            if char == "'":
                if i + 1 < length and line[i + 1] == "'":
                    i += 2
                    continue
                in_single = False
            i += 1
            continue
        if in_double:
            if char == "\\":
                i += 2
                continue
            if char == '"':
                in_double = False
            i += 1
            continue
        if char == "'":
            in_single = True
        elif char == '"':
            in_double = True
        elif char == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip(), False, False
        i += 1
    return line, in_single, in_double


def _iter_sanitized_lines(text: str) -> Iterator[tuple]:
    """Yield ``(body, ending, is_block_content)`` for each physical line.

    Comments are removed from ordinary lines.  Lines that are part of a block
    scalar (``|`` / ``>``) are yielded untouched: there ``#`` is data, not a
    comment.  Quoted regions are respected so ``"# not a comment"`` survives.
    """
    block_indent = None
    in_single = False
    in_double = False

    for raw in text.splitlines(keepends=True):
        body = raw.rstrip("\r\n")
        ending = raw[len(body):]

        if block_indent is not None:
            if body.strip() == "":
                yield body, ending, True
                continue
            indent = len(body) - len(body.lstrip(" "))
            if indent > block_indent:
                yield body, ending, True
                continue
            block_indent = None

        sanitized, in_single, in_double = _strip_line_comment(body, in_single, in_double)
        if not (in_single or in_double) and _BLOCK_HEADER_RE.search(sanitized):
            block_indent = len(body) - len(body.lstrip(" "))
        yield sanitized, ending, False


def alias_count(text: Any) -> int:
    """Count alias references (``*name``) in *text*.

    Comments, quoted scalars and block-scalar bodies are ignored.  This is a
    cheap upper-bound used alongside the node-expansion limit in
    :func:`safe_load`.
    """
    if not isinstance(text, str):
        return 0
    count = 0
    for body, _ending, is_block in _iter_sanitized_lines(text):
        if is_block:
            continue
        count += len(_ALIAS_RE.findall(body))
    return count


# ---------------------------------------------------------------------------
# Comment sanitisation
# ---------------------------------------------------------------------------

def sanitize_comment(text: Any) -> str:
    """Return *text* with YAML comments removed.

    Comments are a common place for secrets to leak into logs and error
    messages.  ``#`` inside quoted scalars or block scalars is left alone.
    Non-string input yields an empty string (nothing to leak).
    """
    if not isinstance(text, str):
        return ""
    return "".join(
        body + ending for body, ending, _is_block in _iter_sanitized_lines(text)
    )


# ---------------------------------------------------------------------------
# Document count
# ---------------------------------------------------------------------------

def is_single_document(text: Any) -> bool:
    """Return ``True`` only when *text* contains exactly one YAML document.

    Empty input, multi-document streams and unparseable input all return
    ``False`` so that a stream cannot hide extra documents from validation.
    """
    if not isinstance(text, str):
        return False
    if _flow_nesting_exceeded(text, MAX_FLOW_NESTING):
        return False
    count = 0
    try:
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.DocumentStartEvent):
                count += 1
                if count > 1:
                    return False
    except Exception:
        return False
    return count == 1


# ---------------------------------------------------------------------------
# Node-level policy used by the validating loader
# ---------------------------------------------------------------------------

def _iter_children(node: Node) -> Iterator[Node]:
    if isinstance(node, MappingNode):
        for key, value in node.value:
            yield key
            yield value
    elif isinstance(node, SequenceNode):
        yield from node.value


def _validate_node_tree(
    root: Node,
    *,
    max_depth: int,
    max_scalar_chars: int,
    max_expansions: int,
) -> None:
    """Validate a composed document without constructing Python objects.

    Enforces the tag policy, the nesting-depth limit, per-scalar length and a
    hard cap on the number of node expansions (which also terminates cyclic
    alias graphs and bounds "billion laughs" style fan-out).
    """
    stack = [(root, 1)]
    expansions = 0

    while stack:
        node, depth = stack.pop()
        expansions += 1
        if expansions > max_expansions:
            raise YamlGuardError("document expands to too many nodes (aliases)")
        if depth > max_depth:
            raise YamlGuardError(f"document nesting exceeds {max_depth} levels")

        if not isinstance(node.tag, str) or _is_unsafe_tag(node.tag):
            raise YamlGuardError(f"unsafe YAML tag: {node.tag!r}")

        if isinstance(node, ScalarNode):
            if len(node.value) > max_scalar_chars:
                raise YamlGuardError("scalar exceeds the maximum length")
            if node.tag == TAG_BOOL and node.value.lower() not in _STRICT_BOOLS:
                raise YamlGuardError(
                    f"ambiguous boolean {node.value!r}; use true/false or quote it"
                )
            continue

        for child in _iter_children(node):
            stack.append((child, depth + 1))


_ALLOWED_SCALARS = (str, int, float, bool, type(None))


def _strict_check_value(value: Any, *, max_depth: int) -> None:
    """Reject constructed values outside the configuration data model.

    Only ``dict``/``list``/``str``/``int``/``float``/``bool``/``None`` are
    allowed; mapping keys must be strings.  This blocks ``!!set``,
    ``!!timestamp``, ``!!binary`` and similar constructs that a safe loader
    may still produce but that a configuration layer should never accept.
    """
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise YamlGuardError(f"document nesting exceeds {max_depth} levels")
        if isinstance(current, _ALLOWED_SCALARS):
            continue
        if isinstance(current, dict):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise YamlGuardError("mapping keys must be strings")
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
            continue
        if isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))
            continue
        raise YamlGuardError(
            f"unsupported YAML value type: {type(current).__name__}"
        )


# ---------------------------------------------------------------------------
# Validating loader
# ---------------------------------------------------------------------------

def _flow_nesting_exceeded(text: str, limit: int) -> bool:
    """Cheap linear scan for pathological flow-collection nesting.

    Runs before PyYAML ever sees the document.  Comments and quoted scalars
    are honoured so brackets inside them are not counted.
    """
    depth = 0
    in_single = False
    in_double = False

    for body, _ending, is_block in _iter_sanitized_lines(text):
        if is_block:
            continue
        i = 0
        length = len(body)
        while i < length:
            char = body[i]
            if in_single:
                if char == "'":
                    # '' is an escaped quote inside a single-quoted scalar.
                    if i + 1 < length and body[i + 1] == "'":
                        i += 2
                        continue
                    in_single = False
            elif in_double:
                if char == "\\":
                    i += 2
                    continue
                if char == '"':
                    in_double = False
            elif char == "'":
                in_single = True
            elif char == '"':
                in_double = True
            elif char in "[{":
                depth += 1
                if depth > limit:
                    return True
            elif char in "]}":
                depth -= 1
                if depth < 0:
                    # Unbalanced closers: let the parser report the error.
                    return False
            i += 1
    return False


def _check_text(text: Any, max_chars: int) -> None:
    if not isinstance(text, str):
        raise YamlGuardError("YAML input must be a string")
    if len(text) > max_chars:
        raise YamlGuardError(f"document exceeds {max_chars} characters")
    if _flow_nesting_exceeded(text, MAX_FLOW_NESTING):
        raise YamlGuardError(
            f"document nesting exceeds {MAX_FLOW_NESTING} levels"
        )


def safe_load_all(
    text: str,
    *,
    max_chars: int = MAX_INPUT_CHARS,
    max_depth: int = MAX_DEPTH,
    max_aliases: int = MAX_ALIASES,
    max_scalar_chars: int = MAX_SCALAR_CHARS,
    max_expansions: int = MAX_ALIAS_EXPANSIONS,
) -> list:
    """Validate every document in *text* and return the loaded values.

    Each document is validated independently for tags, duplicate/merge keys,
    depth, scalar length and alias expansion before anything is constructed.
    Construction always uses ``SafeLoader`` and the resulting values are then
    checked against the strict configuration type model.
    """
    _check_text(text, max_chars)
    if alias_count(text) > max_aliases:
        raise YamlGuardError(f"document contains more than {max_aliases} aliases")
    if has_python_tag(text):
        raise YamlGuardError("document contains a forbidden YAML tag")

    try:
        nodes = list(yaml.compose_all(text))
    except RecursionError as exc:
        raise YamlGuardError("document nesting is too deep to parse") from exc
    except yaml.YAMLError as exc:
        raise YamlGuardError(f"invalid YAML: {exc}") from exc

    if _documents_have_duplicate_keys(nodes):
        raise YamlGuardError("document contains duplicate or overridden keys")

    for node in nodes:
        _validate_node_tree(
            node,
            max_depth=max_depth,
            max_scalar_chars=max_scalar_chars,
            max_expansions=max_expansions,
        )

    try:
        # Explicit SafeLoader: never yaml.load()/FullLoader/UnsafeLoader.
        values = list(yaml.load_all(text, Loader=yaml.SafeLoader))
    except RecursionError as exc:
        raise YamlGuardError("document nesting is too deep to construct") from exc
    except yaml.YAMLError as exc:
        raise YamlGuardError(f"invalid YAML: {exc}") from exc

    if len(values) != len(nodes):
        raise YamlGuardError("document stream changed during validation")

    for value in values:
        _strict_check_value(value, max_depth=max_depth)

    return values


def safe_load(
    text: str,
    *,
    max_chars: int = MAX_INPUT_CHARS,
    max_depth: int = MAX_DEPTH,
    max_aliases: int = MAX_ALIASES,
    max_scalar_chars: int = MAX_SCALAR_CHARS,
    max_expansions: int = MAX_ALIAS_EXPANSIONS,
) -> Any:
    """Safely load a single YAML document, raising :class:`YamlGuardError`.

    This is the entry point configuration code should use instead of
    ``yaml.load``.  Multi-document streams are rejected here; use
    :func:`safe_load_all`, which validates every document.
    """
    values = safe_load_all(
        text,
        max_chars=max_chars,
        max_depth=max_depth,
        max_aliases=max_aliases,
        max_scalar_chars=max_scalar_chars,
        max_expansions=max_expansions,
    )
    if len(values) != 1:
        raise YamlGuardError(
            f"expected exactly one YAML document, found {len(values)}"
        )
    return values[0]
