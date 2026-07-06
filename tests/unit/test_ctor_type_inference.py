"""Typing an unannotated ``__init__`` parameter from its construction site.

Charms build sub-components as ``self.backup = PostgreSQLBackups(self, ...)`` -- passing
the charm as an *unannotated* ``charm`` parameter the component stores (``self.charm =
charm``). Without a type, a cross-object byte-sink call through it
(``self.charm._patroni.render_file(<unordered>)``) can't resolve its receiver and a real
flap is missed. These tests pin the construction-site inference that closes it, its
generic (non-``self``) forms, and its conservative ambiguity handling.
"""

from __future__ import annotations


def test_untyped_charm_backreference_is_typed_from_construction(lint_source):
    # The postgresql pgbackrest shape: an unordered set reaches a file through a
    # cross-object ``self.charm._patroni.render_file(...)`` where ``self.charm`` is an
    # unannotated ctor param. Inferring its type (the charm constructs the component
    # with ``self``) makes the flap visible.
    findings = lint_source(
        """
        class Patroni:
            def render_file(self, path: str, content: str, mode: int) -> None:
                with open(path, "w+") as f:
                    f.write(content)

        class Charm:
            @property
            def _peer_ips(self):
                return set(self._raw())
            @property
            def _patroni(self) -> Patroni:
                return Patroni()
            def __init__(self):
                self.backup = Backups(self, "s3")

        class Backups:
            def __init__(self, charm, relation_name):
                self.charm = charm
            def render(self):
                self.charm._patroni.render_file("/p", ",".join(self.charm._peer_ips), 0o640)
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_param_typed_from_constructor_argument(lint_source):
    # Generic (not ``self``): the stored param is typed from a *nested constructor*
    # argument, so ``self.src.items`` resolves to Producer's unordered property.
    findings = lint_source(
        """
        class Producer:
            @property
            def items(self):
                return set(self._raw())
        class Writer:
            def __init__(self, src):
                self.src = src
            def flush(self):
                self._container.push("/p", ",".join(self.src.items))
        class App:
            def build(self):
                return Writer(Producer())
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_param_typed_from_class_annotated_argument(lint_source):
    # Generic: the construction argument is itself a class-annotated parameter.
    findings = lint_source(
        """
        class Producer:
            @property
            def items(self):
                return set(self._raw())
        class Writer:
            def __init__(self, src):
                self.src = src
            def flush(self):
                self._container.push("/p", ",".join(self.src.items))
        class App:
            def build(self, p: "Producer"):
                return Writer(p)
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_conflicting_construction_types_are_not_inferred(lint_source):
    # Safety: constructed with two different classes across sites -> ambiguous -> the
    # attribute is left untyped rather than mis-resolved. (No false positive from a
    # wrongly-imported summary; the flap here simply stays out of reach, which is the
    # conservative choice.)
    findings = lint_source(
        """
        class A:
            @property
            def items(self):
                return set(self._raw())
        class B:
            @property
            def items(self):
                return sorted(self._raw())
        class Writer:
            def __init__(self, src):
                self.src = src
            def flush(self):
                self._container.push("/p", ",".join(self.src.items))
        class App:
            def build(self):
                Writer(A())
                Writer(B())
        """
    )
    assert not any(f.sink == "file" for f in findings)


def test_free_function_param_typed_from_call_site(lint_source):
    # The general form (not a constructor): a free function's unannotated param is
    # typed from what the call passes, so a receiver use inside its body resolves.
    findings = lint_source(
        """
        class Charm:
            @property
            def _peer_ips(self):
                return set(self._raw())
            def go(self):
                _render(self)

        def _render(charm):
            charm._container.push("/p", ",".join(charm._peer_ips))
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_uniquely_named_method_param_typed_from_call_site(lint_source):
    # A uniquely-named method's unannotated param is typed the same way.
    findings = lint_source(
        """
        class Helper:
            def render_with(self, charm):
                charm._container.push("/p", ",".join(charm._peer_ips))
        class Charm:
            @property
            def _peer_ips(self):
                return set(self._raw())
            def go(self):
                Helper().render_with(self)
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_shared_method_name_resolves_via_known_receiver_class(lint_source):
    # A method name shared across classes still resolves *precisely* when the
    # receiver's class is known -- ``(class, method)`` is the unique key. ``H1()`` is a
    # fresh constructor, so ``H1.render_with``'s param is typed even though ``H2`` also
    # defines ``render_with``.
    findings = lint_source(
        """
        class Charm:
            @property
            def _peer_ips(self):
                return set(self._raw())
            def go(self):
                H1().render_with(self)
        class H1:
            def render_with(self, charm):
                charm._container.push("/p", ",".join(charm._peer_ips))
        class H2:
            def render_with(self, x):
                pass
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_shared_method_name_on_unknown_receiver_is_not_typed(lint_source):
    # Safety boundary: when the receiver's class is *unknown* (an unannotated
    # ``helper`` param) AND the method name is shared, there is no way to pick the
    # right callee, so the param is left untyped rather than risking a wrong-summary
    # false positive. (A globally-unique method name would still resolve.)
    findings = lint_source(
        """
        class Charm:
            @property
            def _peer_ips(self):
                return set(self._raw())
            def go(self, helper):
                helper.render_with(self)
        class H1:
            def render_with(self, charm):
                charm._container.push("/p", ",".join(charm._peer_ips))
        class H2:
            def render_with(self, x):
                pass
        """
    )
    assert not any(f.sink == "file" for f in findings)


def test_annotation_still_wins_over_inference(lint_source):
    # An explicit annotation is authoritative: inference never overwrites it. A
    # component annotated with the real charm type resolves exactly as before.
    findings = lint_source(
        """
        class Charm:
            @property
            def _peer_ips(self):
                return set(self._raw())
        class Backups:
            def __init__(self, charm: "Charm", relation_name):
                self.charm = charm
            def render(self):
                self._container.push("/p", ",".join(self.charm._peer_ips))
        """
    )
    assert any(f.sink == "file" for f in findings)
