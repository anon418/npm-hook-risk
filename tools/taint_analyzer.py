"""JavaScript install hook용 AST 기반 source-to-sink taint 분석.

환경 변수, 민감 파일 읽기, CI/CD secret 같은 source가 외부 통신, 명령 실행,
파일 쓰기 sink로 흘러가는지를 제한된 깊이에서 추적한다. 정적 근거 생성용이며
악성 행위 부재를 증명하지 않는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

try:
    from ast_utils import (
        get_call_name,
        get_string_literal,
        member_name,
        node_line,
        parse_js,
        source_text,
    )
    from taint_rules import SINKS, SOURCES
except ImportError:
    from tools.ast_utils import (
        get_call_name,
        get_string_literal,
        member_name,
        node_line,
        parse_js,
        source_text,
    )
    from tools.taint_rules import SINKS, SOURCES

# 정적 분석이 무한 재귀/복잡한 제어흐름에 빠지지 않도록 깊이를 제한한다.
MAX_ANALYSIS_DEPTH = 100
MAX_INTERPROCEDURAL_DEPTH = 1


@dataclass(frozen=True)
class PropagationStep:
    """오염된 값이 지나간 변수 바인딩 또는 호출 경계."""

    var: str
    line: int | None
    kind: str
    key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the propagation step for JSON output."""
        result = {"var": self.var, "line": self.line, "kind": self.kind}
        if self.key is not None:
            result["key"] = self.key
        return result


@dataclass(frozen=True)
class TaintInfo:
    """source의 출처와 현재 값까지의 전파 경로."""

    source_type: str
    source_expression: str
    source_file: str
    source_line: int | None
    propagation: tuple[PropagationStep, ...] = ()

    def with_step(self, step: PropagationStep) -> "TaintInfo":
        """Return a copy extended with one propagation step."""
        return TaintInfo(
            source_type=self.source_type,
            source_expression=self.source_expression,
            source_file=self.source_file,
            source_line=self.source_line,
            propagation=(*self.propagation, step),
        )


@dataclass(frozen=True)
class TaintPath:
    """하나의 완성된 source-to-sink 경로."""

    source: dict[str, Any]
    propagation: list[dict[str, Any]]
    sink: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the taint path for JSON output."""
        return {
            "source": self.source,
            "propagation": self.propagation,
            "sink": self.sink,
        }


@dataclass
class TaintState:
    """현재 변수 taint, 모듈 alias, HTTP request handle 상태."""

    tainted_vars: dict[str, list[TaintInfo]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    request_handles: dict[str, str | None] = field(default_factory=dict)
    static_strings: dict[str, str] = field(default_factory=dict)
    url_objects: dict[str, str] = field(default_factory=dict)

    def copy(self) -> "TaintState":
        """Copy state containers while preserving immutable taint records."""
        return TaintState(
            tainted_vars={
                name: list(infos) for name, infos in self.tainted_vars.items()
            },
            aliases=dict(self.aliases),
            request_handles=dict(self.request_handles),
            static_strings=dict(self.static_strings),
            url_objects=dict(self.url_objects),
        )


class TaintAnalyzer:
    """JavaScript 파일 하나에 대해 제한된 데이터 흐름 분석을 수행한다."""

    def __init__(self, source: str, file_name: str = "<memory>") -> None:
        self.source = source
        self.file_name = file_name
        # parse 실패는 빈 taint 결과로 처리한다. 실패 상태 자체는 상위 analyzer가 기록한다.
        self.ast = parse_js(source)
        self.functions: dict[str, Any] = {}
        self.paths: list[TaintPath] = []
        self._path_keys: set[tuple[Any, ...]] = set()

    def analyze(self) -> list[TaintPath]:
        """top-level 코드와 같은 파일 내 1-hop 함수 호출만 분석한다."""
        if self.ast is None:
            return []
        self._index_functions(self.ast.body)
        self._process_statements(
            self.ast.body,
            TaintState(),
            interprocedural_depth=0,
            ast_depth=0,
        )
        return self.paths

    def _index_functions(self, statements: list[Any]) -> None:
        """Index same-file function declarations and function assignments."""
        for statement in statements:
            if statement.type == "FunctionDeclaration" and statement.id:
                self.functions[statement.id.name] = statement
            elif statement.type == "VariableDeclaration":
                for declaration in statement.declarations:
                    init_type = getattr(declaration.init, "type", None)
                    if (
                        declaration.id.type == "Identifier"
                        and init_type in {"FunctionExpression", "ArrowFunctionExpression"}
                    ):
                        self.functions[declaration.id.name] = declaration.init

    def _canonical_name(self, raw_name: str | None, state: TaintState) -> str | None:
        """Resolve the first component of a call or member through aliases."""
        if raw_name is None:
            return None
        first, separator, remainder = raw_name.partition(".")
        alias = state.aliases.get(first)
        if alias is None:
            return raw_name
        resolved = alias + (separator + remainder if separator else "")
        if resolved.startswith("child_process."):
            return resolved.removeprefix("child_process.")
        return resolved

    def _source_from_expression(
        self, node: Any, state: TaintState
    ) -> list[TaintInfo]:
        """직접 source로 볼 수 있는 표현식을 식별한다."""
        node_type = getattr(node, "type", None)
        member = self._canonical_name(member_name(node), state)
        call_name = (
            self._canonical_name(get_call_name(node), state)
            if node_type == "CallExpression"
            else None
        )

        for source_type in ("ci_cd_secrets", "environment_access"):
            for pattern in SOURCES[source_type].get("member_patterns", []):
                if member and re.search(pattern, member):
                    return [self._new_info(source_type, node)]

        if node_type != "CallExpression":
            return []

        for source_type, rules in SOURCES.items():
            if call_name in rules.get("call_names", []):
                if source_type == "sensitive_file_read":
                    first_arg = node.arguments[0] if node.arguments else None
                    path = get_string_literal(first_arg)
                    if path is None or not any(
                        re.search(pattern, path)
                        for pattern in rules.get("literal_path_patterns", [])
                    ):
                        continue
                return [self._new_info(source_type, node)]
        return []

    def _new_info(self, source_type: str, node: Any) -> TaintInfo:
        """Create taint information from a source AST node."""
        return TaintInfo(
            source_type=source_type,
            source_expression=source_text(node, self.source),
            source_file=self.file_name,
            source_line=node_line(node),
        )

    def _expression_taint(
        self, node: Any, state: TaintState, ast_depth: int
    ) -> list[TaintInfo]:
        """표현식이 운반하는 taint 정보를 계산한다."""
        if node is None or ast_depth > MAX_ANALYSIS_DEPTH:
            return []
        direct = self._source_from_expression(node, state)
        if direct:
            return direct

        node_type = node.type
        if node_type == "Identifier":
            return list(state.tainted_vars.get(node.name, []))
        if node_type == "MemberExpression":
            root = self._root_identifier(node)
            return self._unique_infos(
                (list(state.tainted_vars.get(root, [])) if root else [])
                + self._expression_taint(node.object, state, ast_depth + 1)
            )
        if node_type in {"LogicalExpression", "BinaryExpression"}:
            return self._unique_infos(
                self._expression_taint(node.left, state, ast_depth + 1)
                + self._expression_taint(node.right, state, ast_depth + 1)
            )
        if node_type in {"ConditionalExpression"}:
            return self._unique_infos(
                self._expression_taint(node.consequent, state, ast_depth + 1)
                + self._expression_taint(node.alternate, state, ast_depth + 1)
            )
        if node_type == "ObjectExpression":
            infos: list[TaintInfo] = []
            for prop in node.properties:
                if prop.type == "SpreadElement":
                    prop_infos = self._expression_taint(
                        prop.argument, state, ast_depth + 1
                    )
                    key = "..."
                else:
                    prop_infos = self._expression_taint(
                        prop.value, state, ast_depth + 1
                    )
                    key = (
                        getattr(prop.key, "name", None)
                        or get_string_literal(prop.key)
                        or "<computed>"
                    )
                infos.extend(
                    info.with_step(
                        PropagationStep(
                            var="<object>",
                            line=node_line(prop),
                            kind="object_embed",
                            key=key,
                        )
                    )
                    for info in prop_infos
                )
            return self._unique_infos(infos)
        if node_type == "ArrayExpression":
            infos = []
            for index, element in enumerate(node.elements):
                infos.extend(
                    info.with_step(
                        PropagationStep(
                            var="<array>",
                            line=node_line(element),
                            kind="array_embed",
                            key=str(index),
                        )
                    )
                    for info in self._expression_taint(
                        element, state, ast_depth + 1
                    )
                )
            return self._unique_infos(infos)
        if node_type == "CallExpression":
            infos = []
            callee_object = getattr(node.callee, "object", None)
            infos.extend(
                self._expression_taint(callee_object, state, ast_depth + 1)
            )
            for argument in node.arguments:
                infos.extend(
                    self._expression_taint(argument, state, ast_depth + 1)
                )
            return self._unique_infos(infos)
        if node_type in {"AwaitExpression", "UnaryExpression", "UpdateExpression"}:
            return self._expression_taint(node.argument, state, ast_depth + 1)
        if node_type == "AssignmentExpression":
            return self._expression_taint(node.right, state, ast_depth + 1)
        return []

    def _bind(
        self,
        target: Any,
        value: Any,
        state: TaintState,
        kind: str,
        ast_depth: int,
    ) -> None:
        """표현식 taint와 모듈/request alias를 대상 변수에 묶는다."""
        if target is None:
            return
        if target.type == "ObjectPattern":
            module = self._required_module(value)
            if module:
                for prop in target.properties:
                    local = getattr(prop.value, "name", None)
                    imported = getattr(prop.key, "name", None)
                    if local and imported:
                        state.aliases[local] = f"{module}.{imported}"
            return
        target_name = self._target_name(target)
        if target_name is None:
            return

        module = self._required_module(value)
        if module:
            state.aliases[target_name] = module
        literal = get_string_literal(value)
        if literal is not None:
            state.static_strings[target_name] = literal
        if (
            getattr(value, "type", None) == "NewExpression"
            and member_name(value.callee) == "URL"
            and value.arguments
        ):
            url = self._resolve_static_string(value.arguments[0], state)
            if url is not None:
                state.url_objects[target_name] = url

        call_name = (
            self._canonical_name(get_call_name(value), state)
            if getattr(value, "type", None) == "CallExpression"
            else None
        )
        if call_name in {"https.request", "http.request"}:
            state.request_handles[target_name] = self._find_webhook(value, state)

        infos = self._expression_taint(value, state, ast_depth + 1)
        if infos:
            state.tainted_vars[target_name] = [
                info.with_step(
                    PropagationStep(
                        var=target_name,
                        line=node_line(target),
                        kind=kind,
                    )
                )
                for info in infos
            ]
        else:
            state.tainted_vars.pop(target_name, None)

    def _process_statements(
        self,
        statements: list[Any],
        state: TaintState,
        interprocedural_depth: int,
        ast_depth: int,
    ) -> None:
        """문장을 소스 순서대로 처리하되 재귀 깊이를 제한한다."""
        if ast_depth > MAX_ANALYSIS_DEPTH:
            return
        for statement in statements:
            statement_type = statement.type
            if statement_type == "VariableDeclaration":
                for declaration in statement.declarations:
                    self._bind(
                        declaration.id,
                        declaration.init,
                        state,
                        "assignment_from_source",
                        ast_depth + 1,
                    )
                    self._process_expression(
                        declaration.init,
                        state,
                        interprocedural_depth,
                        ast_depth + 1,
                    )
            elif statement_type == "ExpressionStatement":
                expression = statement.expression
                if expression.type == "AssignmentExpression":
                    self._bind(
                        expression.left,
                        expression.right,
                        state,
                        "assignment",
                        ast_depth + 1,
                    )
                self._process_expression(
                    expression,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )
            elif statement_type == "ReturnStatement":
                self._process_expression(
                    statement.argument,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )
            elif statement_type == "BlockStatement":
                self._process_statements(
                    statement.body,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )
            elif statement_type == "IfStatement":
                self._process_expression(
                    statement.test,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )
                for branch in (statement.consequent, statement.alternate):
                    if branch is None:
                        continue
                    branch_state = state.copy()
                    branch_statements = (
                        branch.body if branch.type == "BlockStatement" else [branch]
                    )
                    self._process_statements(
                        branch_statements,
                        branch_state,
                        interprocedural_depth,
                        ast_depth + 1,
                    )
                    self._merge_state(state, branch_state)
            elif statement_type in {"ForStatement", "WhileStatement", "DoWhileStatement"}:
                body = statement.body
                body_statements = body.body if body.type == "BlockStatement" else [body]
                self._process_statements(
                    body_statements,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )
            elif statement_type == "TryStatement":
                blocks = [statement.block, statement.handler, statement.finalizer]
                for block in blocks:
                    if block is None:
                        continue
                    body = block.body
                    if hasattr(body, "body"):
                        body = body.body
                    self._process_statements(
                        body,
                        state,
                        interprocedural_depth,
                        ast_depth + 1,
                    )

    def _process_expression(
        self,
        node: Any,
        state: TaintState,
        interprocedural_depth: int,
        ast_depth: int,
    ) -> None:
        """Inspect calls, sinks, IIFEs, and nested expressions."""
        if node is None or ast_depth > MAX_ANALYSIS_DEPTH:
            return
        if node.type == "CallExpression":
            call_name = self._canonical_name(get_call_name(node), state)
            self._record_sink(node, call_name, state, ast_depth)

            if call_name in self.functions and (
                interprocedural_depth < MAX_INTERPROCEDURAL_DEPTH
            ):
                self._analyze_called_function(
                    self.functions[call_name],
                    node,
                    state,
                    interprocedural_depth + 1,
                    ast_depth + 1,
                )
            elif node.callee.type in {"FunctionExpression", "ArrowFunctionExpression"}:
                self._analyze_called_function(
                    node.callee,
                    node,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )

            self._process_expression(
                getattr(node.callee, "object", None),
                state,
                interprocedural_depth,
                ast_depth + 1,
            )
            for argument in node.arguments:
                self._process_expression(
                    argument,
                    state,
                    interprocedural_depth,
                    ast_depth + 1,
                )
        elif node.type in {"AssignmentExpression", "LogicalExpression", "BinaryExpression"}:
            self._process_expression(
                node.right, state, interprocedural_depth, ast_depth + 1
            )
            self._process_expression(
                getattr(node, "left", None),
                state,
                interprocedural_depth,
                ast_depth + 1,
            )
        elif node.type == "ObjectExpression":
            for prop in node.properties:
                child = prop.argument if prop.type == "SpreadElement" else prop.value
                self._process_expression(
                    child, state, interprocedural_depth, ast_depth + 1
                )
        elif node.type == "ArrayExpression":
            for element in node.elements:
                self._process_expression(
                    element, state, interprocedural_depth, ast_depth + 1
                )

    def _analyze_called_function(
        self,
        function: Any,
        call: Any,
        caller_state: TaintState,
        interprocedural_depth: int,
        ast_depth: int,
    ) -> None:
        """Analyze a same-file function with tainted actual arguments."""
        function_state = TaintState(
            aliases=dict(caller_state.aliases),
            static_strings=dict(caller_state.static_strings),
            url_objects=dict(caller_state.url_objects),
        )
        for parameter, argument in zip(function.params, call.arguments):
            if parameter.type != "Identifier":
                continue
            infos = self._expression_taint(argument, caller_state, ast_depth + 1)
            if infos:
                function_state.tainted_vars[parameter.name] = [
                    info.with_step(
                        PropagationStep(
                            var=f"{parameter.name} (param)",
                            line=node_line(parameter),
                            kind="function_argument",
                        )
                    )
                    for info in infos
                ]
        body = function.body
        if body.type == "BlockStatement":
            self._process_statements(
                body.body,
                function_state,
                interprocedural_depth,
                ast_depth + 1,
            )
        else:
            self._process_expression(
                body,
                function_state,
                interprocedural_depth,
                ast_depth + 1,
            )

    def _record_sink(
        self,
        node: Any,
        call_name: str | None,
        state: TaintState,
        ast_depth: int,
    ) -> None:
        """Create paths for tainted values passed to a recognized sink."""
        sink_type: str | None = None
        webhook_url = self._find_webhook(node, state)
        if call_name:
            for candidate_type, rules in SINKS.items():
                if candidate_type == "webhook_url":
                    continue
                if call_name in rules.get("call_names", []):
                    sink_type = candidate_type
                    break

        if call_name and call_name.endswith(".write"):
            handle = call_name.rsplit(".", 1)[0]
            if handle in state.request_handles:
                sink_type = "external_communication"
                webhook_url = webhook_url or state.request_handles[handle]

        if sink_type is None:
            return
        for argument in node.arguments:
            infos = self._expression_taint(argument, state, ast_depth + 1)
            for info in infos:
                self._append_path(
                    info,
                    sink_type,
                    call_name or "<unknown>",
                    argument,
                    node,
                    webhook_url,
                )

    def _append_path(
        self,
        info: TaintInfo,
        sink_type: str,
        sink_call: str,
        argument: Any,
        sink_node: Any,
        webhook_url: str | None,
    ) -> None:
        """Append one deduplicated source-to-sink path."""
        key = (
            info.source_type,
            info.source_line,
            info.source_expression,
            sink_type,
            sink_call,
            node_line(sink_node),
        )
        if key in self._path_keys:
            return
        self._path_keys.add(key)
        sink = {
            "type": "webhook_url" if webhook_url else sink_type,
            "call": sink_call,
            "argument": source_text(argument, self.source),
            "file": self.file_name,
            "line": node_line(sink_node),
        }
        if webhook_url:
            sink["webhook_url"] = webhook_url
        self.paths.append(
            TaintPath(
                source={
                    "type": info.source_type,
                    "expression": info.source_expression,
                    "file": info.source_file,
                    "line": info.source_line,
                },
                propagation=[step.to_dict() for step in info.propagation],
                sink=sink,
            )
        )

    def _find_webhook(
        self, node: Any, state: TaintState | None = None
    ) -> str | None:
        """Find a static webhook URL inside an expression tree."""
        if node is None:
            return None
        literal = (
            self._resolve_static_string(node, state)
            if state is not None
            else get_string_literal(node)
        )
        if literal and any(
            re.search(pattern, literal, re.IGNORECASE)
            for pattern in SINKS["webhook_url"]["argument_literal_patterns"]
        ):
            return literal
        for value in vars(node).values():
            if hasattr(value, "type"):
                found = self._find_webhook(value, state)
                if found:
                    return found
            elif isinstance(value, list):
                for item in value:
                    if hasattr(item, "type"):
                        found = self._find_webhook(item, state)
                        if found:
                            return found
        return None

    @staticmethod
    def _resolve_static_string(
        node: Any, state: TaintState | None
    ) -> str | None:
        """Resolve a literal, constant identifier, or URL object member."""
        literal = get_string_literal(node)
        if literal is not None or state is None:
            return literal
        if getattr(node, "type", None) == "Identifier":
            return state.static_strings.get(node.name) or state.url_objects.get(
                node.name
            )
        if getattr(node, "type", None) == "MemberExpression":
            root = TaintAnalyzer._root_identifier(node)
            if root:
                return state.url_objects.get(root)
        return None

    @staticmethod
    def _root_identifier(node: Any) -> str | None:
        """Return the left-most identifier in a member chain."""
        current = node
        while getattr(current, "type", None) == "MemberExpression":
            current = current.object
        return getattr(current, "name", None) if current else None

    @staticmethod
    def _target_name(node: Any) -> str | None:
        """Return a stable variable or member name for an assignment target."""
        if getattr(node, "type", None) == "Identifier":
            return node.name
        return member_name(node)

    @staticmethod
    def _required_module(node: Any) -> str | None:
        """Return the module name for a static require call."""
        if getattr(node, "type", None) != "CallExpression":
            return None
        call_name = get_call_name(node)
        return call_name.removeprefix("require:") if call_name and call_name.startswith("require:") else None

    @staticmethod
    def _unique_infos(infos: list[TaintInfo]) -> list[TaintInfo]:
        """Deduplicate equivalent taint origins and trails."""
        unique: dict[tuple[Any, ...], TaintInfo] = {}
        for info in infos:
            key = (
                info.source_type,
                info.source_line,
                info.source_expression,
                tuple(info.propagation),
            )
            unique[key] = info
        return list(unique.values())

    @staticmethod
    def _merge_state(target: TaintState, source: TaintState) -> None:
        """Merge a best-effort branch state back into its parent."""
        target.aliases.update(source.aliases)
        target.request_handles.update(source.request_handles)
        target.static_strings.update(source.static_strings)
        target.url_objects.update(source.url_objects)
        for name, infos in source.tainted_vars.items():
            target.tainted_vars[name] = TaintAnalyzer._unique_infos(
                target.tainted_vars.get(name, []) + infos
            )


def analyze_source(source: str, file_name: str = "<memory>") -> list[TaintPath]:
    """Analyze JavaScript source and return complete taint paths."""
    return TaintAnalyzer(source, file_name=file_name).analyze()


def analyze_function(
    fn_ast: Any,
    initial_taint: TaintState | None = None,
    source: str = "",
    file_name: str = "<memory>",
) -> list[TaintPath]:
    """Analyze one function AST with an optional initial taint state."""
    analyzer = TaintAnalyzer(source, file_name=file_name)
    analyzer.ast = fn_ast
    state = initial_taint or TaintState()
    body = fn_ast.body if getattr(fn_ast, "type", None) != "Program" else fn_ast
    statements = body.body if hasattr(body, "body") else []
    analyzer._index_functions(statements)
    analyzer._process_statements(statements, state, 0, 0)
    return analyzer.paths
