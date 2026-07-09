"""Downward dispatch: a base method operating on ``self`` may run on a subclass
instance, so a ``self.`` member it reads/calls can be a subclass *override*.

A base aggregator (grafana-agent's ``_loki_config`` reading ``self._additional_
log_configs``) is often an abstract stub or a clean default in the base, with the
real (unstable) implementation in the concrete charm subclass. Resolving only
upward (base + ancestors) loses that override; resolution must also look at
subclass overrides. Applies to overridable members uniformly -- methods,
properties, and instance attributes.
"""

from __future__ import annotations

from conftest import details


def test_base_method_calls_subclass_override(lint_source):
    findings = lint_source(
        """
        import yaml

        class Base:
            def _extra(self):
                raise NotImplementedError          # abstract stub -- clean

            def _config(self):
                return {"logs": self._extra()}      # base reads an overridable member

            def write(self):
                self._container.push("/c", yaml.dump(self._config()))

        class Machine(Base):
            def _extra(self):
                return list({self._a, self._b})     # override: order-unstable
        """
    )
    assert any(f.rule == "unordered-iteration" for f in findings), details(findings)


def test_base_reads_subclass_property_override(lint_source):
    findings = lint_source(
        """
        import yaml

        class Base:
            @property
            def _extra(self):
                raise NotImplementedError

            def _config(self):
                return {"logs": self._extra}         # property read of an overridable member

            def write(self):
                self._container.push("/c", yaml.dump(self._config()))

        class Machine(Base):
            @property
            def _extra(self):
                return list({self._a, self._b})      # override: order-unstable
        """
    )
    assert any(f.rule == "unordered-iteration" for f in findings), details(findings)
