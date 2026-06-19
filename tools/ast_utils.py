"""JavaScript AST 파싱과 노드 접근을 안전하게 감싸는 유틸리티.

기본 파서는 Esprima이며, 연구용 fallback은 provenance를 남기기 위해 별도
parser_attempts를 기록한다. 파서 성공/실패는 coverage 근거이지 탐지 성능이 아니다.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import esprima

LOGGER = logging.getLogger("ast_utils")
# 매우 큰 파일은 분석 안정성을 위해 파싱하지 않는다. 실패는 명시적 coverage 한계다.
MAX_JS_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class ParseAttempt:
    """provenance 기록을 위한 parser 시도 1회와 결과."""

    parser: str
    mode: str
    status: str
    error: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "parser": self.parser,
            "mode": self.mode,
            "status": self.status,
            "error": self.error,
        }


class AstNode:
    """실험용 fallback이 사용하는 작은 ESTree 호환 노드."""

    def __init__(self, type: str, **kwargs: Any) -> None:
        self.type = type
        for key, value in kwargs.items():
            setattr(self, key, value)


def _node(type: str, **kwargs: Any) -> AstNode:
    return AstNode(type, **kwargs)


def parse_js(source: str) -> Any | None:
    """JavaScript를 Esprima Program으로 파싱하고 실패 시 None을 반환한다."""
    ast, _ = parse_js_with_provenance(source, allow_modern_fallback=False)
    return ast


def parse_js_with_provenance(
    source: str,
    allow_modern_fallback: bool = False,
) -> tuple[Any | None, dict[str, Any]]:
    """JavaScript 파싱 결과와 parser chain provenance를 함께 반환한다."""
    # shebang은 Unix 실행 관례지만 ECMAScript 문법은 아니므로 파싱 전에 제거한다.
    if source.startswith("#!"):
        newline_idx = source.find("\n")
        source = source[newline_idx + 1:] if newline_idx != -1 else ""

    attempts: list[ParseAttempt] = []
    if len(source.encode("utf-8")) > MAX_JS_BYTES:
        LOGGER.warning("JavaScript source exceeds the 5MB analysis limit")
        attempts.append(
            ParseAttempt("size_guard", "bytes", "failed", "source exceeds 5MB")
        )
        return None, _parse_provenance(attempts, None)
    options = {"loc": True, "range": True, "tolerant": True}
    try:
        ast = esprima.parseScript(source, options=options)
        attempts.append(ParseAttempt("esprima", "script", "success"))
        return ast, _parse_provenance(attempts, "esprima")
    except Exception as script_error:
        attempts.append(
            ParseAttempt("esprima", "script", "failed", str(script_error))
        )
        try:
            ast = esprima.parseModule(source, options=options)
            attempts.append(ParseAttempt("esprima", "module", "success"))
            return ast, _parse_provenance(attempts, "esprima")
        except Exception as module_error:
            attempts.append(
                ParseAttempt("esprima", "module", "failed", str(module_error))
            )
            # fallback은 Esprima가 실패했을 때만 사용한다. Esprima 성공 결과는 보존한다.
            if allow_modern_fallback:
                ast, error = _parse_modern_fallback(source)
                if ast is not None:
                    attempts.append(
                        ParseAttempt(
                            "lightweight_estree_fallback",
                            "script_or_module",
                            "success",
                        )
                    )
                    return ast, _parse_provenance(
                        attempts, "lightweight_estree_fallback"
                    )
                attempts.append(
                    ParseAttempt(
                        "lightweight_estree_fallback",
                        "script_or_module",
                        "failed",
                        error,
                    )
                )
            LOGGER.warning("JavaScript parse failed: %s", script_error)
            return None, _parse_provenance(attempts, None)


def _parse_provenance(
    attempts: list[ParseAttempt],
    parser_used: str | None,
) -> dict[str, Any]:
    return {
        "parser_primary": "esprima",
        "parser_fallback": (
            "lightweight_estree_fallback"
            if any(attempt.parser == "lightweight_estree_fallback" for attempt in attempts)
            else None
        ),
        "parser_used": parser_used,
        "parser_attempts": [attempt.to_dict() for attempt in attempts],
    }


def _parse_modern_fallback(source: str) -> tuple[Any | None, str]:
    """Esprima가 거부한 최신 문법을 보수적인 ESTree Program으로 축약한다."""
    if re.search(r"\b(?:const|let|var)\s*=", source):
        return None, "malformed variable declaration"
    body: list[Any] = []
    for match in re.finditer(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        source,
    ):
        body.append(
            _node(
                "VariableDeclaration",
                declarations=[
                    _node(
                        "VariableDeclarator",
                        id=_identifier(match.group(1)),
                        init=_call(_identifier("require"), [_literal(match.group(2))]),
                    )
                ],
            )
        )
    for match in re.finditer(
        r"\b(?:await\s+)?import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        source,
    ):
        body.append(
            _node(
                "ExpressionStatement",
                expression=_call(_identifier("import"), [_literal(match.group(1))]),
            )
        )
    for match in re.finditer(
        r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(",
        source,
    ):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "catch", "function", "import"}:
            continue
        body.append(_node("ExpressionStatement", expression=_call(_member(name), [])))
    return _node("Program", body=body), ""


def _identifier(name: str) -> AstNode:
    return _node("Identifier", name=name)


def _literal(value: str) -> AstNode:
    return _node("Literal", value=value)


def _call(callee: Any, arguments: list[Any]) -> AstNode:
    return _node("CallExpression", callee=callee, arguments=arguments)


def _member(name: str) -> Any:
    parts = name.split(".")
    current: Any = _identifier(parts[0])
    for part in parts[1:]:
        current = _node(
            "MemberExpression",
            object=current,
            property=_identifier(part),
            computed=False,
        )
    return current


def _child_nodes(node: Any) -> list[Any]:
    """Return AST-valued children from an Esprima node."""
    children: list[Any] = []
    values = node.items() if isinstance(node, dict) else vars(node).items()
    for key, value in values:
        if key in {"loc", "range", "tokens", "errors"}:
            continue
        if hasattr(value, "type"):
            children.append(value)
        elif isinstance(value, list):
            children.extend(item for item in value if hasattr(item, "type"))
    return children


def walk(
    node: Any,
    visitor: Callable[[Any, list[Any]], None],
    depth_limit: int = 100,
) -> None:
    """Walk an AST depth-first and call visitor with each node and parents."""

    def visit(current: Any, parents: list[Any], depth: int) -> None:
        if current is None or depth > depth_limit:
            if depth > depth_limit:
                LOGGER.warning("AST traversal stopped at depth limit %d", depth_limit)
            return
        visitor(current, parents)
        for child in _child_nodes(current):
            visit(child, [*parents, current], depth + 1)

    visit(node, [], 0)


def member_name(node: Any) -> str | None:
    """Return a dotted name for an Identifier or MemberExpression."""
    node_type = getattr(node, "type", None)
    if isinstance(node, dict):
        node_type = node.get("type")
    if node_type == "Identifier":
        return getattr(node, "name", None) if not isinstance(node, dict) else node.get("name")
    if node_type == "ThisExpression":
        return "this"
    if node_type == "CallExpression":
        call_name = get_call_name(node)
        if call_name and call_name.startswith("require:"):
            return call_name.removeprefix("require:")
        return None
    if node_type != "MemberExpression":
        return None

    object_value = node.get("object") if isinstance(node, dict) else node.object
    object_name = member_name(object_value)
    if object_name is None:
        return None
    computed = node.get("computed") if isinstance(node, dict) else node.computed
    property_value = node.get("property") if isinstance(node, dict) else node.property
    if computed:
        property_name = get_string_literal(property_value)
    else:
        property_name = (
            property_value.get("name")
            if isinstance(property_value, dict)
            else getattr(property_value, "name", None)
        )
    if property_name is None:
        return None
    return f"{object_name}.{property_name}"


def get_call_name(call_node: Any) -> str | None:
    """Identify the target of a JavaScript CallExpression."""
    if getattr(call_node, "type", None) != "CallExpression":
        return None
    callee = call_node.get("callee") if isinstance(call_node, dict) else call_node.callee
    arguments = call_node.get("arguments", []) if isinstance(call_node, dict) else call_node.arguments
    callee_name = member_name(callee)
    if callee_name == "require" and arguments:
        module_name = get_string_literal(arguments[0])
        return f"require:{module_name}" if module_name is not None else "require"
    return callee_name


def get_string_literal(node: Any) -> str | None:
    """Extract a static string from a Literal or TemplateLiteral."""
    node_type = node.get("type") if isinstance(node, dict) else getattr(node, "type", None)
    if node_type == "Literal":
        value = node.get("value") if isinstance(node, dict) else node.value
        return value if isinstance(value, str) else None
    if node_type != "TemplateLiteral" or node.expressions:
        return None
    return "".join(
        getattr(quasi.value, "cooked", None)
        or getattr(quasi.value, "raw", "")
        for quasi in node.quasis
    )


def node_line(node: Any) -> int | None:
    """Return the one-based starting line for an AST node."""
    loc = node.get("loc") if isinstance(node, dict) else getattr(node, "loc", None)
    start = getattr(loc, "start", None)
    return getattr(start, "line", None)


def source_text(node: Any, source: str) -> str:
    """Return the original source slice represented by an AST node."""
    node_range = getattr(node, "range", None)
    if not node_range or len(node_range) != 2:
        return ""
    return source[node_range[0] : node_range[1]]
