"""Assignment-expression (walrus ``:=``) taint binding.

A ``(name := expr)`` binds ``name`` in the enclosing scope, so ``name`` carries
``expr``'s value for the rest of the block -- the ``if certs := get_all():`` guard
idiom. flaplint used to track only plain ``name = expr`` statements, so a
walrus-guarded unstable value looked untainted and its flap was silently missed
(the grafana ``_trusted_ca_certs`` cert-bundle chain). These tests pin the fix and
its guarantee that a walrus is treated identically to the two-line assign form.
"""

from __future__ import annotations


def test_walrus_in_if_guard_binds_unordered_source(lint_source):
    # ``if certs := <unordered>:`` then join+write the walrus name -- the grafana
    # trusted-CA shape (a set joined unsorted into a pushed file).
    findings = lint_source(
        """
        class Charm:
            def _update(self):
                if certs := set(self._raw_certs()):
                    self._container.push("/certs", "\\n".join(certs))
        """
    )
    assert any(f.sink == "file" and f.confidence == "high" for f in findings)


def test_walrus_in_while_guard_binds_unordered_source(lint_source):
    findings = lint_source(
        """
        class Charm:
            def _update(self):
                while chunk := set(self._next()):
                    self._container.push("/p", ",".join(chunk))
                    break
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_walrus_equivalent_to_plain_assign(lint_source):
    # The invariant: a walrus guard flags exactly what the two-line
    # ``x = f(); if x:`` form flags -- no more, no less.
    walrus = lint_source(
        """
        class Charm:
            def h(self):
                if data := set(self._raw()):
                    self.relation.data[self.app]["k"] = ",".join(data)
        """
    )
    twoline = lint_source(
        """
        class Charm:
            def h(self):
                data = set(self._raw())
                if data:
                    self.relation.data[self.app]["k"] = ",".join(data)
        """
    )
    sig = lambda fs: sorted((f.rule, f.sink) for f in fs)
    assert sig(walrus) == sig(twoline)
    assert sig(walrus)  # and it is non-empty (both genuinely flag)


def test_walrus_binding_a_sorted_value_stays_clean(lint_source):
    # A walrus does not over-taint: binding an already-sorted value leaves the
    # write clean, exactly as the plain-assign form would.
    findings = lint_source(
        """
        import json
        class Charm:
            def h(self):
                if certs := sorted(set(self._raw())):
                    self.relation.data[self.app]["k"] = json.dumps(certs)
        """
    )
    assert not any(f.sink == "databag" for f in findings)
