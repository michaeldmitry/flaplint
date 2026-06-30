"""Tests for taint flow through Jinja2-style ``template.render(**ctx)`` calls.

The analyzer can't see inside a ``.j2`` template, so it treats a render as text
built from its arguments: if an unstable value is rendered and the result reaches a
sink, it flaps. This is the ``setup_logrotate_config`` shape in mysql-k8s, where the
order-dependent iteration lives in the template rather than in the Python.
"""

from __future__ import annotations


def test_local_set_rendered_into_databag_is_flagged(lint_source):
    # A locally-born set rendered into text and written to a databag: the rendered
    # bytes flap. A concrete caller bug.
    findings = lint_source(
        """
        import jinja2

        class Charm:
            def publish(self, units):
                template = jinja2.Template(open("t.j2").read())
                rendered = template.render(members={u for u in units})
                self.relation.data[self.app]["cfg"] = rendered
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_collection_param_rendered_into_databag_is_a_contract_sink(lint_source):
    # A parameter annotated as unordered, rendered into text and written to a
    # databag: the helper owns a contract-boundary ``sink`` finding, graded high by
    # the annotation. (The render is what carries the parameter's taint to the
    # write -- without it the flow is invisible.)
    findings = lint_source(
        """
        import jinja2
        from typing import Iterable

        class Charm:
            def publish(self, enabled_log_files: Iterable):
                template = jinja2.Template(open("t.j2").read())
                rendered = template.render(files=enabled_log_files)
                self.relation.data[self.app]["cfg"] = rendered
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "high"          # Iterable annotation
    assert sinks[0].variable == "enabled_log_files"


def test_local_set_rendered_into_file_is_flagged(lint_source):
    # A concrete unstable value rendered into a file (container.push) is reported
    # for any sink kind, not just databags.
    findings = lint_source(
        """
        import jinja2

        class Charm:
            def publish(self, units):
                template = jinja2.Template(open("t.j2").read())
                rendered = template.render(members={u for u in units})
                self.container.push("/etc/cfg", rendered)
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_sorted_render_argument_is_clean(lint_source):
    # Sorting the value before handing it to the template removes the instability.
    findings = lint_source(
        """
        import jinja2

        class Charm:
            def publish(self, units):
                template = jinja2.Template(open("t.j2").read())
                rendered = template.render(members=sorted({u for u in units}))
                self.relation.data[self.app]["cfg"] = rendered
        """
    )
    assert findings == []


def test_render_result_not_reaching_a_sink_is_not_flagged(lint_source):
    # If the rendered text never reaches a sink, there is nothing to report.
    findings = lint_source(
        """
        import jinja2

        class Charm:
            def render_only(self, units):
                template = jinja2.Template(open("t.j2").read())
                return template.render(members={u for u in units})
        """
    )
    assert [f for f in findings if f.sink in ("databag", "file", "hash")] == []


def test_ordered_param_rendered_is_not_flagged(lint_source):
    # A parameter annotated as already-ordered is the caller's responsibility, so
    # rendering it into a sink is not a contract-boundary finding on this helper.
    findings = lint_source(
        """
        import jinja2
        from typing import List

        class Charm:
            def publish(self, items: List[str]):
                template = jinja2.Template(open("t.j2").read())
                self.relation.data[self.app]["cfg"] = template.render(items=items)
        """
    )
    assert findings == []


def test_user_defined_render_method_uses_its_own_summary(lint_source):
    # When the codebase defines its own ``render`` that sorts, the heuristic must
    # step aside and use that summary -- so a sorted render is clean.
    findings = lint_source(
        """
        class Renderer:
            def render(self, values):
                return ",".join(sorted(values))

        class Charm:
            def publish(self, units):
                r = Renderer()
                self.relation.data[self.app]["cfg"] = r.render({u for u in units})
        """
    )
    assert findings == []
