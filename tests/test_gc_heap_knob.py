"""GC-heap knob: max_gc_heap_mb (see benchmarks/pocs/README.md).

wasmtime-py 47 binds no GC-heap limiter (Store.set_limits covers linear
memory only), so the knob is validated, recorded in the security baseline
and forwarded through the worker, but does not (yet) change engine config.
Overfilling the GC heap stays bound by max_fuel.
"""

import wasmtime

from ephemora_cell import ExecutionReport, WASIConfig, WASISandbox, config_fingerprint
from ephemora_cell.process_executor import run_isolated

SIMPLE_WAT = b"""
(module
  (func (export "main") (result i32) i32.const 42)
)
"""


def _simple_wasm(tmp_path) -> str:
    wasm_file = tmp_path / "simple.wasm"
    wasm_file.write_bytes(wasmtime.wat2wasm(SIMPLE_WAT))
    return str(wasm_file)


class TestGcHeapKnob:
    @staticmethod
    def _base_report():
        return ExecutionReport(
            status="success", exit_code=0, elapsed_ms=1.0
        ).apply_config

    def test_default_is_none(self, tmp_path):
        assert self._base_report()(WASIConfig()).security_baseline["gc_heap_mb"] is None

    def test_recorded_in_baseline(self, tmp_path):
        report = self._base_report()(WASIConfig(max_gc_heap_mb=128))
        assert report.security_baseline["gc_heap_mb"] == 128

    def test_forwarded_through_worker(self, tmp_path):
        config = WASIConfig(max_gc_heap_mb=256)
        payload = run_isolated(_simple_wasm(tmp_path), config, args=[])
        assert payload["security_baseline"]["gc_heap_mb"] == 256

    def test_worker_baseline_authoritative(self, tmp_path):
        """Worker baseline must mirror effective config, not defaults."""
        config = WASIConfig(max_memory_mb=64, max_gc_heap_mb=128)
        payload = run_isolated(_simple_wasm(tmp_path), config, args=[])
        baseline = payload["security_baseline"]
        assert baseline["memory_limit_bytes"] == 64 * 1024 * 1024
        assert baseline["gc_heap_mb"] == 128

    def test_rejects_non_positive(self, tmp_path):
        for bad in (0, -1):
            try:
                WASISandbox(WASIConfig(max_gc_heap_mb=bad))
            except ValueError:
                continue
            raise AssertionError(f"max_gc_heap_mb={bad} accepted")

    def test_does_not_change_engine_fingerprint(self):
        a = config_fingerprint(WASIConfig())
        b = config_fingerprint(WASIConfig(max_gc_heap_mb=512))
        assert a == b

    def test_report_to_dict_keeps_knob(self, tmp_path):
        report = self._base_report()(WASIConfig(max_gc_heap_mb=64))
        assert report.to_dict()["security_baseline"]["gc_heap_mb"] == 64
