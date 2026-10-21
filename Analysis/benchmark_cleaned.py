import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from scipy.optimize import minimize_scalar

import matplotlib.pyplot as plt

# Outlier threshold: remove samples farther than this many standard deviations
# from the mean of their action/permission group.
MAX_VARIANCE = 2.0

# Offset bounds in nanoseconds.
# Non-negative offsets only; adjust MAX_BASELINE_OFFSET_NS if needed.
MIN_BASELINE_OFFSET_NS = 0.0
MAX_BASELINE_OFFSET_NS = 100_000_000.0

from DrawGraph.draw_permission_in_action import plot_permission_action_matrix
from Pipelines.costantPath import (
    OUTPUT_MAPPING_AWARE_PATH,
    OUTPUT_MAPPING_AGNOSTIC_PATH,
    OUTPUT_DEFAULT_ALLOW_PATH,
    OUTPUT_BENCHMARK_DIR,
    CHECK_FOR_ACTION_PATH,
)


class OPABenchmark:
    """
    Benchmark Mapping Aware vs Mapping Agnostic authorization.

    Mapping Aware:
        One OPA request for the complete action.

    Mapping Agnostic:
        One OPA request per required permission.
        Evaluation short-circuits at the first denied permission.

    Default allow:
        It defines a reference where each request are just allowed without any evaluation.
        It is used to measure the timer_rego_query_eval_ns  of the OPA request itself, without any evaluation.

    Logical test:
        (testId, repetition)

    For each logical test:
        - calls = number of executed OPA requests
        - total timer_rego_query_eval_ns time = sum of executed OPA evaluation times
        - decision = DENY if the first executed denied permission is found;
                     otherwise ALLOW
        - passed = final decision == expectedAllowed

    This makes Mapping Aware and Mapping Agnostic directly comparable at the same
    x-axis position.
    """

    def __init__(
        self,
        mapping_aware_file: str | Path,
        mapping_agnostic_file: str | Path,
        default_allow_file: str | Path,
        output_dir: str | Path,
    ):
        self.mapping_aware_file = Path(mapping_aware_file)
        self.mapping_agnostic_file = Path(mapping_agnostic_file)
        self.default_allow_file = Path(default_allow_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.mapping_aware = self._load(self.mapping_aware_file)
        self.mapping_agnostic = self._load(self.mapping_agnostic_file)
        self.default_allow = self._load(self.default_allow_file)

    # ==========================================================
    # LOAD
    # ==========================================================

    @staticmethod
    def _load(path: Path) -> List[Dict[str, Any]]:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, list):
            raise ValueError(f"Benchmark file must contain a JSON list: {path}")

        return data

    # ==========================================================
    # HELPERS
    # ==========================================================

    @staticmethod
    def _test_key(result: Dict[str, Any]) -> Tuple[Any, Any]:
        return (
            result.get("testId"),
            result.get("repetition"),
        )

    @staticmethod
    def _executed(result: Dict[str, Any]) -> bool:
        """
        A mapping_agnostic row is an executed OPA request when it has timing data.

        This also handles explicitly skipped rows produced by the runner:
        skipped rows have no timer_rego_query_eval_ns timing.
        """
        return result.get("opaEvalNs") is not None

    @staticmethod
    def _ns(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _format_ns(value: Optional[float]) -> str:
        if value is None:
            return "N/A"
        if value >= 1_000_000:
            return f"{value / 1_000_000:.3f} ms"
        if value >= 1_000:
            return f"{value / 1_000:.3f} µs"
        return f"{value:.0f} ns"

    @staticmethod
    def _percentile(values: List[float], percentile: float) -> Optional[float]:
        if not values:
            return None

        values = sorted(values)

        if len(values) == 1:
            return values[0]

        position = (percentile / 100) * (len(values) - 1)
        lower = int(position)
        upper = lower + 1

        if upper >= len(values):
            return values[-1]

        weight = position - lower
        return values[lower] + weight * (values[upper] - values[lower])

    def _statistics(self, values: List[float]) -> Dict[str, Optional[float]]:
        if not values:
            return {
                "count": 0,
                "mean": None,
                "median": None,
                "p95": None,
                "p99": None,
                "min": None,
                "max": None,
            }

        return {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "p95": self._percentile(values, 95),
            "p99": self._percentile(values, 99),
            "min": min(values),
            "max": max(values),
        }

    # ==========================================================
    # LOGICAL TEST AGGREGATION
    # ==========================================================

    def _aggregate_mapping_aware(self) -> List[Dict[str, Any]]:
        """One row per logical test, preserving unmeasured tests."""
        rows = []

        for result in self.mapping_aware:
            has_timing = result.get("opaEvalNs") is not None
            decision_value = result.get("opaActual")

            # A test without a decision or timing is not a measured evaluation.
            decision = (
                bool(decision_value)
                if decision_value is not None and has_timing
                else None
            )
            expected = bool(result.get("expectedAllowed"))

            rows.append({
                "testId": result.get("testId"),
                "repetition": result.get("repetition"),
                "securityGroup": result.get("securityGroup"),
                "action": result.get("action"),
                "expectedAllowed": expected,
                "decision": decision,
                "passed": decision == expected if decision is not None else None,
                "calls": 1 if has_timing else 0,
                "total_timer_rego_query_eval_ns": (
                    self._ns(result.get("opaEvalNs")) if has_timing else None
                ),
                "total_opa_handler_ns": (
                    self._ns(result.get("opaHandlerNs"))
                    if result.get("opaHandlerNs") is not None
                    else None
                ),
                "rows": [result],
            })

        return rows


    def _action_call_series(self):
        """Single source of truth for the 'OPA calls per action' line.

        Returns (actions, aware_calls, agnostic_calls). Used by BOTH
        plot_test_comparison() and plot_action_mean_ratio().
        """
        paired_aware, paired_agnostic = self._paired_tests()
        actions = sorted({
            (t.get("action") or "UNKNOWN")
            for t in paired_aware + paired_agnostic
        })
        aware_map = self._max_calls_by_action(paired_aware)
        agnostic_map = self._max_calls_by_action(paired_agnostic)
        aware_calls = [aware_map.get(a, 0) for a in actions]
        agnostic_calls = [agnostic_map.get(a, 0) for a in actions]
        return actions, aware_calls, agnostic_calls

    def _aggregate_default_allow(self) -> List[Dict[str, Any]]:
        """One row per Default Allow logical test.

        Default Allow always allows when it executes, but missing timing data
        means the test cannot be treated as an evaluated result.
        """
        rows = []

        for result in self.default_allow:
            has_timing = result.get("opaEvalNs") is not None
            decision = True if has_timing else None
            expected = bool(result.get("expectedAllowed"))

            rows.append({
                "testId": result.get("testId"),
                "repetition": result.get("repetition"),
                "securityGroup": result.get("securityGroup"),
                "action": result.get("action"),
                "expectedAllowed": expected,
                "decision": decision,
                "passed": decision == expected if decision is not None else None,
                "calls": 1 if has_timing else 0,
                "total_timer_rego_query_eval_ns": (
                    self._ns(result.get("opaEvalNs")) if has_timing else None
                ),
                "total_opa_handler_ns": (
                    self._ns(result.get("opaHandlerNs"))
                    if result.get("opaHandlerNs") is not None
                    else None
                ),
                "rows": [result],
            })

        return rows

    def _aggregate_mapping_agnostic(self) -> List[Dict[str, Any]]:
        """Aggregate executed permission requests per logical test.

        Missing executions are marked as unmeasured, not as authorization denials.
        """
        groups: Dict[Tuple[Any, Any], List[Dict[str, Any]]] = {}

        for result in self.mapping_agnostic:
            groups.setdefault(self._test_key(result), []).append(result)

        aggregated = []

        for key, rows in groups.items():
            rows = sorted(
                rows,
                key=lambda r: (
                    r.get("permissionIndex")
                    if r.get("permissionIndex") is not None
                    else 10 ** 9
                ),
            )

            executed = [r for r in rows if self._executed(r)]
            expected = bool(
                (executed[0] if executed else rows[0]).get("expectedAllowed")
            )

            if not executed:
                decision = None
                total_latency = None
                total_handler = None
                calls = 0
            else:
                first_denied = next(
                    (r for r in executed if r.get("opaActual") is False),
                    None,
                )

                # If any executed permission has an invalid/missing decision,
                # do not silently treat it as ALLOW.
                decisions_valid = all(
                    isinstance(r.get("opaActual"), bool) for r in executed
                )

                if not decisions_valid:
                    decision = None
                else:
                    decision = first_denied is None

                total_latency = sum(
                    self._ns(r.get("opaEvalNs")) for r in executed
                )

                handler_values = [
                    self._ns(r.get("opaHandlerNs"))
                    for r in executed
                    if r.get("opaHandlerNs") is not None
                ]
                total_handler = (
                    sum(handler_values) if handler_values else None
                )

                # Count actual executed request rows. Do not infer calls from
                # permissionIndex because indexes can contain gaps.
                calls = len(executed)

            aggregated.append({
                "testId": key[0],
                "repetition": key[1],
                "securityGroup": rows[0].get("securityGroup"),
                "action": rows[0].get("action"),
                "expectedAllowed": expected,
                "decision": decision,
                "passed": (
                    decision == expected if decision is not None else None
                ),
                "calls": calls,
                "total_timer_rego_query_eval_ns": total_latency,
                "total_opa_handler_ns": total_handler,
                "rows": rows,
            })

        aggregated.sort(
            key=lambda r: (
                r["testId"] if r["testId"] is not None else 10 ** 9,
                r["repetition"] if r["repetition"] is not None else 10 ** 9,
            )
        )

        return aggregated

    def _paired_tests(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Put Mapping Aware and Mapping Agnostic logical tests in the same x-axis order.

        Pairing is done by (testId, repetition).
        """
        mapping_aware = {
            self._test_key(row): row
            for row in self._aggregate_mapping_aware()
        }
        mapping_agnostic = {
            self._test_key(row): row
            for row in self._aggregate_mapping_agnostic()
        }

        keys = sorted(
            set(mapping_aware) | set(mapping_agnostic),
            key=lambda k: (
                k[0] if k[0] is not None else 10**9,
                k[1] if k[1] is not None else 10**9,
            ),
        )

        return (
            [mapping_aware[k] for k in keys if k in mapping_aware],
            [mapping_agnostic[k] for k in keys if k in mapping_agnostic],
        )

    # ==========================================================
    # SUMMARY
    # ==========================================================

    def _mode_summary(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(tests)

        evaluated = [
            test for test in tests
            if test.get("decision") is not None
        ]

        passed = sum(
            1 for test in evaluated if test.get("passed") is True
        )
        failed = len(evaluated) - passed
        unmeasured = total - len(evaluated)

        filtered_tests = self._filter_tests_by_action(tests)

        times = [
            test["total_timer_rego_query_eval_ns"]
            for test in filtered_tests
            if test.get("calls", 0) > 0
               and test.get("total_timer_rego_query_eval_ns") is not None
        ]

        calls = [test.get("calls", 0) for test in tests]

        return {
            "logicalTests": total,
            "evaluatedTests": len(evaluated),
            "unmeasuredTests": unmeasured,
            "passedTests": passed,
            "failedTests": failed,
            "accuracy": passed / len(evaluated) if evaluated else 0.0,
            "totalOpaExecutions": sum(calls),
            "averageCallsPerTest": statistics.mean(calls) if calls else 0.0,
            "minCalls": min(calls) if calls else 0,
            "maxCalls": max(calls) if calls else 0,
            "total_timer_rego_query_eval_ns": self._statistics(times),
            "latencyOutlierFiltering": (
                f"Per action, {MAX_VARIANCE} standard deviations"
            ),
        }

    def summary(self) -> Dict[str, Any]:
        mapping_aware = self._aggregate_mapping_aware()
        mapping_agnostic = self._aggregate_mapping_agnostic()
        default_allow = self._aggregate_default_allow()

        return {
            "mapping_aware": self._mode_summary(mapping_aware),
            "mapping_agnostic": self._mode_summary(mapping_agnostic),
            "default_allow": self._mode_summary(default_allow),
        }

    @staticmethod
    def _filter_outliers(values: List[Dict[str, Any]], value_key: str) -> List[Dict[str, Any]]:
        """
        Filter outliers using the group's mean and standard deviation.

        First calculate the population variance and its standard deviation for
        this action/permission group. Keep a sample when its distance from the
        original mean is at most MAX_VARIANCE standard deviations:

            abs(value - mean) <= MAX_VARIANCE * standard_deviation

        MAX_VARIANCE is therefore a standard-deviation multiplier, not a
        percentage. For example, 2.0 means a sample more than 2 standard
        deviations from the mean is removed. Downstream averages use only the
        retained samples and their actual count.
        """
        if len(values) < 2:
            return list(values)

        numeric = [float(item[value_key]) for item in values]
        mean_value = statistics.mean(numeric)
        variance = statistics.pvariance(numeric)
        standard_deviation = variance ** 0.5

        # If all values are identical, variance is zero and there are no
        # statistical outliers to remove.
        if standard_deviation == 0:
            return list(values)

        threshold = MAX_VARIANCE * standard_deviation
        return [
            item for item in values
            if abs(float(item[value_key]) - mean_value) <= threshold
        ]

    @staticmethod
    def _max_calls_by_action(tests: List[Dict[str, Any]]) -> Dict[str, int]:
        """Return maximum logical-test OPA calls per action.

        Shared by both action-level plots so their orange call-count values
        cannot diverge because of separate grouping or aggregation logic.
        """
        grouped_calls: Dict[str, int] = {}
        for test in tests:
            action = test.get("action") or "UNKNOWN"
            calls = int(test.get("calls", 0) or 0)
            grouped_calls[action] = max(grouped_calls.get(action, 0), calls)
        return grouped_calls

    @classmethod
    def _mapping_agnostic_calls_for_actions(
        cls, tests: List[Dict[str, Any]], actions: List[str]
    ) -> List[int]:
        """Canonical Mapping Agnostic call-count series shared by both plots."""
        calls_by_action = cls._max_calls_by_action(tests)
        return [calls_by_action.get(action, 0) for action in actions]

    @classmethod
    def _filter_tests_by_action(
            cls,
            tests: List[Dict[str, Any]],
            value_key: str = "total_timer_rego_query_eval_ns",
    ) -> List[Dict[str, Any]]:
        """Filter latency outliers independently for each action."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for test in tests:
            value = test.get(value_key)

            if test.get("calls", 0) <= 0 or value is None:
                continue

            action = test.get("action") or "UNKNOWN"
            grouped.setdefault(action, []).append(test)

        filtered = []

        for action_tests in grouped.values():
            filtered.extend(cls._filter_outliers(action_tests, value_key))

        return filtered

    # ==========================================================
    # ACTION TIME STATISTICS
    # ==========================================================

    @staticmethod
    def _action_statistics(
            tests: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """
        Min / average / max total test time for each action.
        """
        grouped: Dict[str, List[float]] = {}

        filtered_tests = OPABenchmark._filter_tests_by_action(tests)
        for test in filtered_tests:
            action = test.get("action") or "UNKNOWN"
            if test["calls"] == 0:
                continue
            grouped.setdefault(action, []).append(test["total_timer_rego_query_eval_ns"])

        return {
            action: {
                "count": len(values),
                "minNs": min(values),
                "avgNs": statistics.mean(values),
                "maxNs": max(values),
            }
            for action, values in sorted(grouped.items())
        }

    def _permission_statistics(self) -> Dict[str, Dict[str, Any]]:
        """
        Mapping Agnostic permission-level min / average / max timer_rego_query_eval_ns latency.

        Skipped permissions are excluded because they did not execute.
        """
        grouped: Dict[str, List[float]] = {}

        for result in self.mapping_agnostic:
            if not self._executed(result):
                continue

            permission = result.get("operation") or "UNKNOWN"
            grouped.setdefault(permission, []).append(
                self._ns(result.get("opaEvalNs"))
            )

        filtered_grouped: Dict[str, List[float]] = {}
        for permission, values in grouped.items():
            samples = [{"latency": value} for value in values]
            filtered_grouped[permission] = [
                sample["latency"]
                for sample in self._filter_outliers(samples, "latency")
            ]

        return {
            permission: {
                "count": len(values),
                "minNs": min(values),
                "avgNs": statistics.mean(values),
                "maxNs": max(values),
            }
            for permission, values in sorted(filtered_grouped.items())
            if values
        }

    def detailed_statistics(self) -> Dict[str, Any]:
        mapping_aware = self._aggregate_mapping_aware()
        mapping_agnostic = self._aggregate_mapping_agnostic()
        default_allow = self._aggregate_default_allow()

        return {
            "mapping_awareByAction": self._action_statistics(mapping_aware),
            "mapping_agnosticByAction": self._action_statistics(mapping_agnostic),
            "default_allowByAction": self._action_statistics(default_allow),
            "mapping_agnosticByPermission": self._permission_statistics(),
        }

    # ==========================================================
    # PRINT
    # ==========================================================

    def print_summary(self) -> None:
        summary = self.summary()

        print()
        print("=" * 90)
        print("OPA BENCHMARK")
        print("=" * 90)

        for mode in ("mapping_aware", "mapping_agnostic", "default_allow"):
            m = summary[mode]

            print()
            print(mode.upper())
            print("-" * 90)
            print(f"Logical tests:          {m['logicalTests']}")
            print(f"Passed:                 {m['passedTests']}")
            print(f"Failed:                 {m['failedTests']}")
            print(f"Accuracy:               {m['accuracy']:.2%}")
            print(f"OPA executions:         {m['totalOpaExecutions']}")
            print(f"Average calls/test:     {m['averageCallsPerTest']:.2f}")
            print(f"Min calls/test:         {m['minCalls']}")
            print(f"Max calls/test:         {m['maxCalls']}")
            print(f"Evaluated tests:        {m['evaluatedTests']}")
            print(f"Unmeasured tests:       {m['unmeasuredTests']}")

            latency = m["total_timer_rego_query_eval_ns"]
            print()
            print("Total timer_rego_query_eval_ns per logical test:")
            print(f"  Average:              {self._format_ns(latency['mean'])}")
            print(f"  Median:               {self._format_ns(latency['median'])}")
            print(f"  P95:                  {self._format_ns(latency['p95'])}")
            print(f"  P99:                  {self._format_ns(latency['p99'])}")
            print(f"  Min:                  {self._format_ns(latency['min'])}")
            print(f"  Max:                  {self._format_ns(latency['max'])}")

    def print_detailed_statistics(self) -> None:
        details = self.detailed_statistics()

        def print_table(title: str, data: Dict[str, Dict[str, Any]]) -> None:
            print()
            print("=" * 110)
            print(title)
            print("=" * 110)
            print(
                f"{'Name':45}"
                f"{'Count':>10}"
                f"{'Min':>18}"
                f"{'Avg':>18}"
                f"{'Max':>18}"
            )
            print("-" * 110)

            for name, values in data.items():
                print(
                    f"{name[:45]:45}"
                    f"{values['count']:>10}"
                    f"{self._format_ns(values['minNs']):>18}"
                    f"{self._format_ns(values['avgNs']):>18}"
                    f"{self._format_ns(values['maxNs']):>18}"
                )

        print_table(
            "MAPPING AWARE — TOTAL TIME BY ACTION",
            details["mapping_awareByAction"],
        )
        print_table(
            "MAPPING AGNOSTIC — TOTAL TIME BY ACTION",
            details["mapping_agnosticByAction"],
        )
        print_table(
            "DEFAULT ALLOW — TOTAL TIME BY ACTION",
            details["default_allowByAction"],
        )
        print_table(
            "MAPPING AGNOSTIC — TIME BY PERMISSION",
            details["mapping_agnosticByPermission"],
        )


    # ==========================================================
    # GRAPH 1 + 2 + 3
    # ==========================================================

    def plot_test_comparison(self) -> None:
        """Compare calls, Rego evaluation time, and authorization results by action.

        All three subplots share the same action categories and ordering. This
        intentionally uses the same action-level aggregation as the orange
        OPA-call line in plot_action_mean_ratio(): maximum calls observed among
        all logical tests/repetitions for each action.
        """
        mapping_aware, mapping_agnostic = self._paired_tests()
        if not mapping_aware and not mapping_agnostic:
            return

        # Apply the existing per-action latency outlier filter.
        filtered_aware = self._filter_tests_by_action(mapping_aware)
        filtered_agnostic = self._filter_tests_by_action(mapping_agnostic)

        def group_by_action(tests):
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for test in tests:
                action = test.get("action") or "UNKNOWN"
                grouped.setdefault(action, []).append(test)
            return grouped

        aware_groups = group_by_action(mapping_aware)
        agnostic_groups = group_by_action(mapping_agnostic)
        filtered_aware_groups = group_by_action(filtered_aware)
        filtered_agnostic_groups = group_by_action(filtered_agnostic)
        actions = sorted(set(aware_groups) | set(agnostic_groups))
        if not actions:
            return

        positions = list(range(1, len(actions) + 1))
        labels = actions

        # Shared action-level aggregation used by both graphs.
        actions, aware_calls, agnostic_calls = self._action_call_series()
        if not actions:
            return
        positions = list(range(1, len(actions) + 1))
        labels = actions

        def latency_samples(grouped, action):
            return [
                t["total_timer_rego_query_eval_ns"] / 1_000_000
                for t in grouped.get(action, [])
                if t.get("calls", 0) > 0 and t.get("total_timer_rego_query_eval_ns") is not None
            ]

        aware_times = [latency_samples(filtered_aware_groups, a) for a in actions]
        agnostic_times = [latency_samples(filtered_agnostic_groups, a) for a in actions]

        def pass_rate(grouped, action):
            tests = [
                t for t in grouped.get(action, [])
                if t.get("decision") is not None
            ]

            return (
                sum(1 for t in tests if t.get("passed") is True) / len(tests)
                if tests else float("nan")
            )

        aware_pass_rates = [pass_rate(aware_groups, a) for a in actions]
        agnostic_pass_rates = [pass_rate(agnostic_groups, a) for a in actions]

        fig, axes = plt.subplots(3, 1, figsize=(max(16, len(actions) * 0.9), 14), sharex=True)

        # 1. Maximum calls per action. The orange series uses the same
        # aggregation as the orange series in mean_latency_ratio...png.
        axes[0].plot(positions, aware_calls, marker="D", label="Mapping Aware")
        axes[0].plot(positions, agnostic_calls, marker="D", color="darkorange", label="Mapping Agnostic")
        max_call_value = int(max(aware_calls + agnostic_calls, default=1))
        axes[0].set_ylim(0, max_call_value + 1)
        axes[0].set_yticks(list(range(0, max_call_value + 2)))
        axes[0].set_ylabel("Maximum OPA calls")
        axes[0].set_title("Maximum OPA Calls per Action Across Logical Tests and Repetitions")
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)

        # 2. Rego-evaluation-time distributions per action.
        offset = 0.18
        aware_data = [(pos - offset, vals) for pos, vals in zip(positions, aware_times) if vals]
        agnostic_data = [(pos + offset, vals) for pos, vals in zip(positions, agnostic_times) if vals]
        if aware_data:
            axes[1].boxplot(
                [v for _, v in aware_data], positions=[p for p, _ in aware_data],
                widths=0.30, patch_artist=True, manage_ticks=False,
                medianprops={"color": "black"}, boxprops={"facecolor": "lightblue"},
                whiskerprops={"color": "steelblue"}, capprops={"color": "steelblue"},
                flierprops={"marker": ".", "markersize": 4},
            )
        if agnostic_data:
            axes[1].boxplot(
                [v for _, v in agnostic_data], positions=[p for p, _ in agnostic_data],
                widths=0.30, patch_artist=True, manage_ticks=False,
                medianprops={"color": "black"}, boxprops={"facecolor": "salmon"},
                whiskerprops={"color": "firebrick"}, capprops={"color": "firebrick"},
                flierprops={"marker": ".", "markersize": 4},
            )
        from matplotlib.patches import Patch
        axes[1].legend(handles=[
            Patch(facecolor="lightblue", edgecolor="steelblue", label="Mapping Aware"),
            Patch(facecolor="salmon", edgecolor="firebrick", label="Mapping Agnostic"),
        ])
        axes[1].set_ylabel("Total timer_rego_query_eval_ns (ms)")
        axes[1].set_title("Total OPA Rego Evaluation Time per Action — Box Plot")
        axes[1].grid(True, axis="y", alpha=0.3)

        # 3. Authorization success rates per action.
        axes[2].plot(positions, aware_pass_rates, marker="o", label="Mapping Aware")
        axes[2].plot(positions, agnostic_pass_rates, marker="o", label="Mapping Agnostic")
        axes[2].set_ylim(-0.05, 1.05)
        axes[2].set_yticks([0, 0.5, 1])
        axes[2].set_yticklabels(["Failed (0%)", "50% passed", "Passed (100%)"])
        axes[2].set_ylabel("Authorization success rate")
        axes[2].set_title("Authorization Result per Action")
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)
        axes[2].set_xticks(positions)
        axes[2].set_xticklabels(labels, rotation=45, ha="right")
        axes[2].set_xlabel("Action (logical tests and repetitions grouped per action)")

        fig.tight_layout()
        output = self.output_dir / "test_comparison_v2.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # ==========================================================
    # OPA HANDLER TIME BOXPLOT
    # ==========================================================

    def plot_handler_time_comparison(self) -> None:
        """
        Compare total OPA server-handler time per logical test using boxplots.

        Each action has two boxes:
        - Mapping Aware: one handler-time measurement per logical test.
        - Mapping Agnostic: sum of handler times for executed permission requests.

        Samples are filtered for outliers independently by action and mode.
        Values are converted from nanoseconds to milliseconds.
        """
        mapping_aware, mapping_agnostic = self._paired_tests()

        if not mapping_aware and not mapping_agnostic:
            return

        def filter_handler_tests(tests):
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for test in tests:
                if test.get("calls", 0) <= 0:
                    continue
                if test.get("total_opa_handler_ns") is None:
                    continue
                grouped.setdefault(test.get("action") or "UNKNOWN", []).append(test)

            filtered: List[Dict[str, Any]] = []
            for action_tests in grouped.values():
                filtered.extend(
                    self._filter_outliers(action_tests, "total_opa_handler_ns")
                )
            return filtered

        filtered_aware = filter_handler_tests(mapping_aware)
        filtered_agnostic = filter_handler_tests(mapping_agnostic)

        actions = sorted({
            test.get("action") or "UNKNOWN"
            for test in filtered_aware + filtered_agnostic
        })
        if not actions:
            return

        aware_by_action: Dict[str, List[float]] = {action: [] for action in actions}
        agnostic_by_action: Dict[str, List[float]] = {action: [] for action in actions}

        for test in filtered_aware:
            action = test.get("action") or "UNKNOWN"
            aware_by_action[action].append(test["total_opa_handler_ns"] / 1_000_000)

        for test in filtered_agnostic:
            action = test.get("action") or "UNKNOWN"
            agnostic_by_action[action].append(test["total_opa_handler_ns"] / 1_000_000)

        # Put the two modes side by side for every action.
        positions = list(range(1, len(actions) + 1))
        offset = 0.18
        aware_positions = [position - offset for position in positions]
        agnostic_positions = [position + offset for position in positions]

        fig, ax = plt.subplots(figsize=(max(14, len(actions) * 1.25), 8))
        aware_data = [aware_by_action[action] for action in actions]
        agnostic_data = [agnostic_by_action[action] for action in actions]

        if any(aware_data):
            valid_positions = [
                position for position, values in zip(aware_positions, aware_data) if values
            ]
            valid_data = [values for values in aware_data if values]
            ax.boxplot(
                valid_data,
                positions=valid_positions,
                widths=0.28,
                patch_artist=True,
                manage_ticks=False,
                boxprops={"facecolor": "lightblue"},
                medianprops={"color": "black", "linewidth": 1.5},
                whiskerprops={"linewidth": 1.2},
                capprops={"linewidth": 1.2},
                flierprops={"marker": "o", "markersize": 3, "alpha": 0.5},
            )

        if any(agnostic_data):
            valid_positions = [
                position for position, values in zip(agnostic_positions, agnostic_data) if values
            ]
            valid_data = [values for values in agnostic_data if values]
            ax.boxplot(
                valid_data,
                positions=valid_positions,
                widths=0.28,
                patch_artist=True,
                manage_ticks=False,
                boxprops={"facecolor": "salmon"},
                medianprops={"color": "black", "linewidth": 1.5},
                whiskerprops={"linewidth": 1.2},
                capprops={"linewidth": 1.2},
                flierprops={"marker": "o", "markersize": 3, "alpha": 0.5},
            )

        from matplotlib.patches import Patch
        ax.legend(
            handles=[
                Patch(facecolor="lightblue", edgecolor="black", label="Mapping Aware"),
                Patch(facecolor="salmon", edgecolor="black", label="Mapping Agnostic"),
            ],
            loc="best",
        )

        ax.set_xticks(positions)
        ax.set_xticklabels(actions, rotation=45, ha="right")
        ax.set_xlabel("Action")
        ax.set_ylabel("Total OPA handler time (ms)")
        ax.set_title("Distribution of Total OPA timer_server_handler_ns Time by Action")
        ax.grid(True, axis="y", alpha=0.3)
        fig.tight_layout()

        output = self.output_dir / "handler_time_comparison_boxplot_v2.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # ==========================================================
    # OPA REGO EVALUATION TIME BOXPLOT PER LOGICAL TEST
    # ==========================================================

    def plot_rego_eval_time_comparison(self) -> None:
        """
        Compare total timer_rego_query_eval_ns per logical test using boxplots.

        Each logical test contributes its total Rego evaluation time. Mapping
        Agnostic totals include only the permission requests actually executed.
        Samples are filtered for outliers independently by action and mode.
        Values are converted from nanoseconds to milliseconds.
        """
        mapping_aware, mapping_agnostic = self._paired_tests()

        if not mapping_aware and not mapping_agnostic:
            return

        metric = "total_timer_rego_query_eval_ns"

        def filter_tests(tests):
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for test in tests:
                if test.get("calls", 0) <= 0 or test.get(metric) is None:
                    continue
                grouped.setdefault(test.get("action") or "UNKNOWN", []).append(test)

            filtered: List[Dict[str, Any]] = []
            for action_tests in grouped.values():
                filtered.extend(self._filter_outliers(action_tests, metric))
            return filtered

        filtered_aware = filter_tests(mapping_aware)
        filtered_agnostic = filter_tests(mapping_agnostic)
        actions = sorted({
            test.get("action") or "UNKNOWN"
            for test in filtered_aware + filtered_agnostic
        })
        if not actions:
            return

        aware_by_action: Dict[str, List[float]] = {action: [] for action in actions}
        agnostic_by_action: Dict[str, List[float]] = {action: [] for action in actions}

        for test in filtered_aware:
            aware_by_action[test.get("action") or "UNKNOWN"].append(
                test[metric] / 1_000_000
            )
        for test in filtered_agnostic:
            agnostic_by_action[test.get("action") or "UNKNOWN"].append(
                test[metric] / 1_000_000
            )

        positions = list(range(1, len(actions) + 1))
        offset = 0.18
        aware_positions = [position - offset for position in positions]
        agnostic_positions = [position + offset for position in positions]

        fig, ax = plt.subplots(figsize=(max(14, len(actions) * 1.25), 8))
        aware_data = [aware_by_action[action] for action in actions]
        agnostic_data = [agnostic_by_action[action] for action in actions]

        if any(aware_data):
            valid = [(pos, vals) for pos, vals in zip(aware_positions, aware_data) if vals]
            ax.boxplot(
                [vals for _, vals in valid], positions=[pos for pos, _ in valid],
                widths=0.28, patch_artist=True, manage_ticks=False,
                boxprops={"facecolor": "lightblue"},
                medianprops={"color": "black", "linewidth": 1.5},
                whiskerprops={"linewidth": 1.2}, capprops={"linewidth": 1.2},
                flierprops={"marker": "o", "markersize": 3, "alpha": 0.5},
            )
        if any(agnostic_data):
            valid = [(pos, vals) for pos, vals in zip(agnostic_positions, agnostic_data) if vals]
            ax.boxplot(
                [vals for _, vals in valid], positions=[pos for pos, _ in valid],
                widths=0.28, patch_artist=True, manage_ticks=False,
                boxprops={"facecolor": "salmon"},
                medianprops={"color": "black", "linewidth": 1.5},
                whiskerprops={"linewidth": 1.2}, capprops={"linewidth": 1.2},
                flierprops={"marker": "o", "markersize": 3, "alpha": 0.5},
            )

        from matplotlib.patches import Patch
        ax.legend(handles=[
            Patch(facecolor="lightblue", edgecolor="black", label="Mapping Aware"),
            Patch(facecolor="salmon", edgecolor="black", label="Mapping Agnostic"),
        ], loc="best")
        ax.set_xticks(positions)
        ax.set_xticklabels(actions, rotation=45, ha="right")
        ax.set_xlabel("Action (each sample is one logical test)")
        ax.set_ylabel("Total timer_rego_query_eval_ns (ms)")
        ax.set_title("Total OPA timer_rego_query_eval_ns Time per Logical Test — Box Plot")
        ax.grid(True, axis="y", alpha=0.3)
        fig.tight_layout()

        output = self.output_dir / "rego_eval_time_per_logical_test_boxplot_v2.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)


    # ==========================================================
    # ACTION MEAN TIME STATISTICS GRAPH
    # ==========================================================
    def plot_action_time_statistics(self) -> None:
        """
        Compare mean total timer_rego_query_eval_ns time per action
        for Mapping Aware and Mapping Agnostic.

        A single grouped column chart is used:
        - X-axis: Actions
        - Y-axis: Mean execution time in milliseconds
        - Two columns per action: Mapping Aware and Mapping Agnostic

        Samples are filtered using the existing per-action outlier filter.
        """
        details = self.detailed_statistics()

        aware = details["mapping_awareByAction"]
        agnostic = details["mapping_agnosticByAction"]

        # Include every action available in either mapping mode.
        actions = sorted(set(aware) | set(agnostic))

        if not actions:
            return

        # Convert mean latency from nanoseconds to milliseconds.
        aware_means = [
            aware[action]["avgNs"] / 1_000_000
            if action in aware else 0.0
            for action in actions
        ]

        agnostic_means = [
            agnostic[action]["avgNs"] / 1_000_000
            if action in agnostic else 0.0
            for action in actions
        ]

        # Create one grouped column chart.
        x = list(range(len(actions)))
        width = 0.38

        fig, ax = plt.subplots(
            figsize=(max(14, len(actions) * 1.1), 8)
        )

        # Mapping Aware columns.
        aware_bars = ax.bar(
            [position - width / 2 for position in x],
            aware_means,
            width=width,
            label="Mapping Aware",
            color="lightblue",
            edgecolor="steelblue",
        )

        # Mapping Agnostic columns.
        agnostic_bars = ax.bar(
            [position + width / 2 for position in x],
            agnostic_means,
            width=width,
            label="Mapping Agnostic",
            color="salmon",
            edgecolor="firebrick",
        )

        # Axis labels and title.
        ax.set_xticks(x)
        ax.set_xticklabels(
            actions,
            rotation=45,
            ha="right",
            rotation_mode="anchor",
        )

        ax.set_xlabel("Action")
        ax.set_ylabel("Mean total OPA evaluation time (ms)")
        ax.set_title(
            "Mean OPA timer_rego_query_eval_ns Time by Action"
        )

        ax.grid(True, axis="y", alpha=0.3)
        ax.set_axisbelow(True)
        ax.legend()

        # Add mean values above the columns.
        ax.bar_label(
            aware_bars,
            fmt="%.3f",
            padding=3,
            fontsize=8,
        )

        ax.bar_label(
            agnostic_bars,
            fmt="%.3f",
            padding=3,
            fontsize=8,
        )

        # Leave room for long, rotated action names and value labels.
        fig.tight_layout()

        output = self.output_dir / "action_time_statistics_v2.png"

        fig.savefig(
            output,
            dpi=300,
            bbox_inches="tight",
        )

        plt.close(fig)

    # ==========================================================
    # THREE-MODE AVERAGE LATENCY GRAPH
    # ==========================================================

    def plot_average_time_three_modes(self) -> None:
        """
        Compare average total timer_rego_query_eval_ns latency per logical action test for:
        Mapping Aware, Mapping Agnostic, and Default Allow.

        Mapping Agnostic time is the sum of the permission requests actually
        executed for that logical test. Default Allow is the no-policy-
        evaluation baseline, not an authorization-equivalent result.
        """
        details = self.detailed_statistics()
        aware = details["mapping_awareByAction"]
        agnostic = details["mapping_agnosticByAction"]
        default = details["default_allowByAction"]

        actions = sorted(set(aware) | set(agnostic) | set(default))
        if not actions:
            return

        x = list(range(len(actions)))
        width = 0.25

        def avg_ms(dataset, action):
            entry = dataset.get(action)
            return entry["avgNs"] / 1_000_000 if entry else 0

        aware_values = [avg_ms(aware, action) for action in actions]
        agnostic_values = [avg_ms(agnostic, action) for action in actions]
        default_values = [avg_ms(default, action) for action in actions]

        fig, ax = plt.subplots(figsize=(max(12, len(actions) * 1.1), 7))
        ax.bar([i - width for i in x], aware_values, width=width, label="Mapping Aware")
        ax.bar(x, agnostic_values, width=width, label="Mapping Agnostic")
        ax.bar([i + width for i in x], default_values, width=width, label="Default Allow")

        ax.set_xticks(x)
        ax.set_xticklabels(actions, rotation=45, ha="right")
        ax.set_xlabel("Action")
        ax.set_ylabel("Average total timer_rego_query_eval_ns (ms)")
        ax.set_title("Average OPA timer_rego_query_eval_ns Time by Action — Three Authorization Modes")
        ax.grid(True, axis="y", alpha=0.3)
        ax.legend()
        fig.tight_layout()

        output = self.output_dir / "average_time_three_modes_v2.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)

    def _mean_permission_request_ns(self) -> Optional[float]:
        """Mean timer_rego_query_eval_ns of one Mapping Agnostic permission request.

        Pools every executed permission request, after the same per-permission
        outlier filter used by _permission_statistics().
        """
        grouped: Dict[str, List[float]] = {}
        for result in self.mapping_agnostic:
            if not self._executed(result):
                continue
            permission = result.get("operation") or "UNKNOWN"
            grouped.setdefault(permission, []).append(self._ns(result.get("opaEvalNs")))

        pooled: List[float] = []
        for values in grouped.values():
            samples = [{"latency": v} for v in values]
            pooled.extend(s["latency"] for s in self._filter_outliers(samples, "latency"))

        return statistics.mean(pooled) if pooled else None

    # ==========================================================
    # MAPPING AWARE / MAPPING AGNOSTIC MEAN RATIO GRAPH
    # ==========================================================

    def plot_action_mean_ratio(self) -> None:
        """
        Plot: mean Mapping Agnostic action latency / mean latency of a single
        Mapping Agnostic permission request (all permissions pooled).

        A ratio of N means the action costs about N average permission requests.
        """
        details = self.detailed_statistics()
        agnostic = details["mapping_agnosticByAction"]

        permission_mean_ns = self._mean_permission_request_ns()
        if not permission_mean_ns:
            return

        actions, _, expected_calls = self._action_call_series()
        if not actions:
            return

        ratios: List[float] = []
        for action in actions:
            entry = agnostic.get(action)
            agnostic_mean = entry.get("avgNs") if entry else None
            ratios.append(
                float("nan") if agnostic_mean is None
                else agnostic_mean / permission_mean_ns
            )

        x = list(range(len(actions)))
        fig, ax = plt.subplots(figsize=(max(12, len(actions) * 1.1), 7))
        bars = ax.bar(x, ratios, label="Action mean latency / mean permission-request latency")
        ax.axhline(1.0, color="gray", linestyle="--", linewidth=1.5,
                   label="One average permission request (ratio = 1)")

        ax.plot(
            x, expected_calls, color="darkorange", marker="D", linestyle="-",
            linewidth=2,
            label="Maximum observed OPA calls per action",
        )

        finite_ratios = [r for r in ratios if r == r]
        top = max(finite_ratios + list(expected_calls), default=1)
        ax.set_ylim(0, top * 1.12)

        ax.set_xticks(x)
        ax.set_xticklabels(actions, rotation=45, ha="right")
        ax.set_xlabel("Action")
        ax.set_ylabel("Latency ratio  /  OPA calls (Mapping Agnostic)")
        ax.set_title(
            "Mapping Agnostic Action Latency over Mean Permission-Request Latency "
            f"(mean request = {permission_mean_ns / 1_000_000:.3f} ms)"
        )
        ax.grid(True, axis="y", alpha=0.3)
        ax.legend(loc="upper left")

        for bar, ratio in zip(bars, ratios):
            if ratio == ratio:
                ax.annotate(
                    f"{ratio:.2f}",
                    (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8,
                )

        fig.tight_layout()
        output = self.output_dir / "mean_latency_ratio_aware_over_agnostic_v2.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)


    # ==========================================================
    # PERMISSION MEAN vs DEFAULT-ALLOW BASELINE
    # ==========================================================


    def _default_allow_mean_ns(self) -> Optional[float]:
        """Mean Default Allow latency after per-action outlier filtering."""
        samples = self._aggregate_default_allow()
        filtered_samples = self._filter_tests_by_action(samples)

        values = [
            test["total_timer_rego_query_eval_ns"]
            for test in filtered_samples
            if test["calls"] > 0
        ]

        return statistics.mean(values) if values else None


    def plot_permission_mean_vs_default_allow(self) -> None:
        """
        Mean timer_rego_query_eval_ns per permission (the 'Average' series of
        permission_time_statistics_v2.png) compared with the Default Allow
        mean, drawn as a constant horizontal line.

        Default Allow is the cost of the OPA request itself with no policy
        evaluation, so the gap between each bar and the line is the time OPA
        needs to actually resolve that permission.
        """
        data = self.detailed_statistics()["mapping_agnosticByPermission"]
        baseline_ns = self._default_allow_mean_ns()
        if not data or baseline_ns is None:
            return

        permissions = list(data.keys())
        x = list(range(len(permissions)))
        means_ms = [data[p]["avgNs"] / 1_000_000 for p in permissions]
        baseline_ms = baseline_ns / 1_000_000

        fig, ax = plt.subplots(figsize=(max(14, len(permissions) * 1.1), 8))

        # Same series as the "Average" line in permission_time_statistics_v2.png
        bars = ax.bar(
            x, means_ms, color="lightblue", edgecolor="steelblue",
            label="Mean per permission (Mapping Agnostic)",
        )
        ax.plot(
            x, means_ms, color="steelblue", marker="o", linewidth=1.5,
        )

        # Constant: Default Allow mean
        ax.axhline(
            baseline_ms, color="darkorange", linestyle="--", linewidth=2,
            label=f"Default Allow mean (constant) = {baseline_ms:.3f} ms",
        )

        ax.bar_label(bars, fmt="%.3f", padding=3, fontsize=8)

        ax.set_xticks(x)
        ax.set_xticklabels(permissions, rotation=45, ha="right")
        ax.set_xlabel("Permission")
        ax.set_ylabel("Mean timer_rego_query_eval_ns (ms)")
        ax.set_title(
            "Mean OPA timer_rego_query_eval_ns per Permission vs Default Allow Baseline"
        )
        ax.set_ylim(0, max(means_ms + [baseline_ms]) * 1.15)
        ax.grid(True, axis="y", alpha=0.3)
        ax.set_axisbelow(True)
        ax.legend(loc="upper left")

        fig.tight_layout()
        output = self.output_dir / "permission_mean_vs_default_allow_v2.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # ==========================================================
    # PERMISSION STATISTICS GRAPH
    # ==========================================================

    def plot_permission_time_statistics(self) -> None:
        """
        Mapping Agnostic permission-level min / average / max timer_rego_query_eval_ns latency.

        All statistics are merged into one line chart.

        X-axis:
            Permission

        Lines:
            Minimum
            Average
            Maximum
        """

        data = self.detailed_statistics()["mapping_agnosticByPermission"]

        if not data:
            return

        permissions = list(data.keys())
        x = list(range(len(permissions)))

        min_values = [
            data[p]["minNs"] / 1_000_000
            for p in permissions
        ]

        avg_values = [
            data[p]["avgNs"] / 1_000_000
            for p in permissions
        ]

        max_values = [
            data[p]["maxNs"] / 1_000_000
            for p in permissions
        ]

        # ------------------------------------------------------
        # Single line chart
        # ------------------------------------------------------

        fig, ax = plt.subplots(
            figsize=(16, 9),
        )

        ax.plot(
            x,
            min_values,
            marker="o",
            linewidth=2,
            label="Minimum",
        )

        ax.plot(
            x,
            avg_values,
            marker="o",
            linewidth=2,
            label="Average",
        )

        ax.plot(
            x,
            max_values,
            marker="o",
            linewidth=2,
            label="Maximum",
        )

        # ------------------------------------------------------
        # Formatting
        # ------------------------------------------------------

        ax.set_xticks(x)

        ax.set_xticklabels(
            permissions,
            rotation=45,
            ha="right",
        )

        ax.set_xlabel("Permission")
        ax.set_ylabel("timer_rego_query_eval_ns (ms)")

        ax.set_title(
            "Mapping Agnostic — Min / Average / Max timer_rego_query_eval_ns Time by Permission"
        )

        ax.grid(
            True,
            alpha=0.3,
        )

        ax.legend()

        fig.tight_layout()

        output = self.output_dir / "permission_time_statistics_v2.png"

        fig.savefig(
            output,
            dpi=300,
            bbox_inches="tight",
        )

        plt.close(fig)


    # ==========================================================
    # BASELINE-RELATIVE EVALUATION COST
    # (SEPARATE MEASURED DEFAULT-ALLOW BASELINES)
    # ==========================================================


    def plot_baseline_relative_cost(self) -> None:
        """
        Compare baseline-relative Mapping Aware and Mapping Agnostic costs.

        Baseline X:
            Mean filtered Default Allow latency per OPA request for Mapping Aware.

        Baseline Y:
            Mean filtered Default Allow latency per OPA request for Mapping Agnostic.

        Mapping Aware incremental cost:
            A_i - B_X

        Mapping Agnostic incremental cost:
            P_i - k_i * B_Y

        Equivalence ratio:
            N* = Mapping Agnostic incremental cost
                 / Mapping Aware incremental cost

        Tests are matched by (testId, repetition).
        """

        # ------------------------------------------------------
        # 1. Calculate the two measured baselines.
        # ------------------------------------------------------
        default_rows = self._aggregate_default_allow()
        filtered_default = self._filter_tests_by_action(default_rows)

        baseline_x_values = [
            float(row["total_timer_rego_query_eval_ns"])
            for row in filtered_default
            if row.get("calls", 0) > 0
            and row.get("total_timer_rego_query_eval_ns") is not None
            and float(row["total_timer_rego_query_eval_ns"]) >= 0
        ]

        # Default Allow is the shared source of baseline measurements.
        # Keep separate lists so the report explicitly records the samples
        # used for each baseline.
        baseline_y_values = list(baseline_x_values)

        if not baseline_x_values:
            print(
                "Baseline-relative graph skipped: no valid, filtered "
                "Default Allow measurements."
            )
            return

        baseline_x_ns = statistics.mean(baseline_x_values)
        baseline_y_ns = statistics.mean(baseline_y_values)

        # ------------------------------------------------------
        # 2. Aggregate and match Mapping Aware / Mapping Agnostic tests.
        # ------------------------------------------------------
        aware_rows = self._aggregate_mapping_aware()
        agnostic_rows = self._aggregate_mapping_agnostic()

        aware_by_key = {
            self._test_key(row): row
            for row in aware_rows
        }
        agnostic_by_key = {
            self._test_key(row): row
            for row in agnostic_rows
        }

        common_keys = set(aware_by_key) & set(agnostic_by_key)

        if not common_keys:
            print(
                "Baseline-relative graph skipped: no matched tests "
                "by (testId, repetition)."
            )
            return

        paired: List[Dict[str, Any]] = []

        for key in sorted(
            common_keys,
            key=lambda k: (
                k[0] if k[0] is not None else 10**9,
                k[1] if k[1] is not None else 10**9,
            ),
        ):
            aware = aware_by_key[key]
            agnostic = agnostic_by_key[key]

            action = aware.get("action") or "UNKNOWN"
            if action != (agnostic.get("action") or "UNKNOWN"):
                continue

            # Only compare tests with valid measured totals.
            aware_total = aware.get("total_timer_rego_query_eval_ns")
            agnostic_total = agnostic.get("total_timer_rego_query_eval_ns")

            if (
                aware.get("calls", 0) <= 0
                or agnostic.get("calls", 0) <= 0
                or aware_total is None
                or agnostic_total is None
            ):
                continue

            aware_ns = float(aware_total)
            agnostic_ns = float(agnostic_total)

            # Count actual executed requests with timing data for this test.
            permission_times = [
                self._ns(result["opaEvalNs"])
                for result in self.mapping_agnostic
                if self._test_key(result) == key
                and self._executed(result)
                and result.get("opaEvalNs") is not None
                and self._ns(result["opaEvalNs"]) >= 0
            ]

            calls = len(permission_times)
            if calls == 0:
                continue

            aware_incremental_ns = aware_ns - baseline_x_ns
            agnostic_incremental_ns = agnostic_ns - calls * baseline_y_ns

            # Negative or zero Mapping Aware incremental cost cannot be a
            # meaningful denominator for this ratio.
            n_star = (
                agnostic_incremental_ns / aware_incremental_ns
                if aware_incremental_ns > 0
                else None
            )

            paired.append({
                "key": key,
                "action": action,
                "aware_ns": aware_ns,
                "agnostic_ns": agnostic_ns,
                "permission_check_count": calls,
                "baseline_x_ns": baseline_x_ns,
                "baseline_y_ns": baseline_y_ns,
                "aware_incremental_ns": aware_incremental_ns,
                "agnostic_incremental_ns": agnostic_incremental_ns,
                "equivalence_n_star": n_star,
            })

        if not paired:
            print(
                "Baseline-relative graph skipped: no matched tests with "
                "valid timings and executed permission requests."
            )
            return

        # ------------------------------------------------------
        # 3. Group matched tests by action.
        # ------------------------------------------------------
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for row in paired:
            grouped.setdefault(row["action"], []).append(row)

        actions = sorted(grouped)

        def mean_us(
            records: List[Dict[str, Any]],
            field: str,
        ) -> float:
            values = [
                float(row[field]) / 1_000
                for row in records
                if row.get(field) is not None
            ]
            return statistics.mean(values) if values else float("nan")

        aware_means = [
            mean_us(grouped[action], "aware_ns")
            for action in actions
        ]
        agnostic_means = [
            mean_us(grouped[action], "agnostic_ns")
            for action in actions
        ]
        aware_incremental = [
            mean_us(grouped[action], "aware_incremental_ns")
            for action in actions
        ]
        agnostic_incremental = [
            mean_us(grouped[action], "agnostic_incremental_ns")
            for action in actions
        ]

        n_star_means = []
        observed_calls = []

        for action in actions:
            records = grouped[action]
            ratios = [
                row["equivalence_n_star"]
                for row in records
                if row["equivalence_n_star"] is not None
            ]

            n_star_means.append(
                statistics.mean(ratios) if ratios else float("nan")
            )
            observed_calls.append(
                statistics.mean(
                    row["permission_check_count"] for row in records
                )
            )

        # ------------------------------------------------------
        # 4. Plot results.
        # ------------------------------------------------------
        x_positions = list(range(len(actions)))
        width = 0.30

        fig, axes = plt.subplots(
            3,
            1,
            figsize=(max(15, len(actions) * 1.15), 16),
            sharex=True,
        )

        # Panel 1: measured total times and per-request baselines.
        axes[0].bar(
            [i - width / 2 for i in x_positions],
            aware_means,
            width,
            label="Mapping Aware total",
            color="lightblue",
            edgecolor="steelblue",
        )
        axes[0].bar(
            [i + width / 2 for i in x_positions],
            agnostic_means,
            width,
            label="Mapping Agnostic total",
            color="salmon",
            edgecolor="firebrick",
        )
        axes[0].axhline(
            baseline_x_ns / 1_000,
            color="steelblue",
            linestyle="--",
            linewidth=2,
            label=f"Baseline X = {baseline_x_ns / 1_000:.3f} µs/request",
        )
        axes[0].axhline(
            baseline_y_ns / 1_000,
            color="darkorange",
            linestyle=":",
            linewidth=2,
            label=f"Baseline Y = {baseline_y_ns / 1_000:.3f} µs/request",
        )
        axes[0].set_ylabel("Mean total time (µs)")
        axes[0].set_title("Measured OPA Evaluation Time")
        axes[0].legend()
        axes[0].grid(True, axis="y", alpha=0.3)
        axes[0].set_axisbelow(True)

        # Panel 2: incremental cost above the appropriate baseline.
        axes[1].bar(
            [i - width / 2 for i in x_positions],
            aware_incremental,
            width,
            label="Mapping Aware: A − B_X",
            color="lightblue",
            edgecolor="steelblue",
        )
        axes[1].bar(
            [i + width / 2 for i in x_positions],
            agnostic_incremental,
            width,
            label="Mapping Agnostic: P − kB_Y",
            color="salmon",
            edgecolor="firebrick",
        )
        axes[1].axhline(0, color="black", linewidth=1)
        axes[1].set_ylabel("Incremental time per test (µs)")
        axes[1].set_title("Incremental Cost Above Separate Baselines")
        axes[1].legend()
        axes[1].grid(True, axis="y", alpha=0.3)
        axes[1].set_axisbelow(True)

        # Panel 3: N* compared with the actual mean number of requests.
        axes[2].bar(
            [i - width / 2 for i in x_positions],
            n_star_means,
            width,
            label="Equivalence ratio N*",
            color="mediumpurple",
        )
        axes[2].bar(
            [i + width / 2 for i in x_positions],
            observed_calls,
            width,
            label="Mean executed permission checks",
            color="darkorange",
        )
        axes[2].axhline(0, color="black", linewidth=1)
        axes[2].set_ylabel("Count / ratio")
        axes[2].set_title("Equivalent Permission Checks: N* vs Actual Calls")
        axes[2].legend()
        axes[2].grid(True, axis="y", alpha=0.3)
        axes[2].set_axisbelow(True)
        axes[2].set_xticks(x_positions)
        axes[2].set_xticklabels(actions, rotation=45, ha="right")
        axes[2].set_xlabel("Action")

        fig.suptitle(
            "Baseline-Relative OPA Cost "
            f"(B_X = {baseline_x_ns / 1_000:.3f} µs, "
            f"B_Y = {baseline_y_ns / 1_000:.3f} µs)",
            fontsize=14,
        )
        fig.tight_layout()

        output = self.output_dir / "baseline_relative_evaluation_cost.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)

        # ------------------------------------------------------
        # 5. Save the JSON report.
        # ------------------------------------------------------
        report: Dict[str, Any] = {
            "matchedLogicalTests": len(paired),
            "unit": "nanoseconds",
            "baselineXNs": baseline_x_ns,
            "baselineYNs": baseline_y_ns,
            "baselineXSamplesUsed": len(baseline_x_values),
            "baselineYSamplesUsed": len(baseline_y_values),
            "baselineSource": (
                "Default Allow measurements after per-action outlier filtering"
            ),
            "method": {
                "baselineX": "Mean filtered Default Allow latency per request",
                "baselineY": "Mean filtered Default Allow latency per request",
                "mappingAware": "aware total - B_X",
                "mappingAgnostic": (
                    "agnostic total - (executed permission request count * B_Y)"
                ),
                "equivalenceNStar": (
                    "Mapping Agnostic incremental cost / "
                    "Mapping Aware incremental cost"
                ),
                "matchingKey": ["testId", "repetition"],
            },
            "actions": {},
        }

        for action in actions:
            records = grouped[action]
            ratios = [
                row["equivalence_n_star"]
                for row in records
                if row["equivalence_n_star"] is not None
            ]

            report["actions"][action] = {
                "matchedTests": len(records),
                "meanMappingAwareNs": statistics.mean(
                    row["aware_ns"] for row in records
                ),
                "meanMappingAgnosticTotalNs": statistics.mean(
                    row["agnostic_ns"] for row in records
                ),
                "meanAwareIncrementalNs": statistics.mean(
                    row["aware_incremental_ns"] for row in records
                ),
                "meanAgnosticIncrementalNs": statistics.mean(
                    row["agnostic_incremental_ns"] for row in records
                ),
                "meanEquivalenceNStar": (
                    statistics.mean(ratios) if ratios else None
                ),
                "meanExecutedPermissionChecks": statistics.mean(
                    row["permission_check_count"] for row in records
                ),
            }

        output_json = (
            self.output_dir / "baseline_relative_evaluation_cost.json"
        )
        with output_json.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)

        print(
            "Measured Mapping Aware baseline X: "
            f"{self._format_ns(baseline_x_ns)}"
        )
        print(
            "Measured Mapping Agnostic baseline Y: "
            f"{self._format_ns(baseline_y_ns)}"
        )
        print(f"Baseline X samples used: {len(baseline_x_values)}")
        print(f"Baseline Y samples used: {len(baseline_y_values)}")
        print(f"Baseline-relative graph written to:\n{output}")
        print(f"Baseline-relative statistics written to:\n{output_json}")



    # ==========================================================
    # SAVE RESULTS
    # ==========================================================

    def save_summary(self) -> Path:
        summary = self.summary()

        output = self.output_dir / "benchmark_summary.json"

        with output.open("w", encoding="utf-8") as file:
            json.dump(summary, file, indent=2)

        return output

    def save_detailed_statistics(self) -> Path:
        details = self.detailed_statistics()

        output = self.output_dir / "benchmark_time_statistics.json"

        with output.open("w", encoding="utf-8") as file:
            json.dump(details, file, indent=2)

        return output

    # ==========================================================
    # RUN
    # ==========================================================

    def run(self) -> None:
        self.print_summary()
        self.print_detailed_statistics()

        self.save_summary()
        self.save_detailed_statistics()

        self.plot_test_comparison()
        self.plot_handler_time_comparison()
        self.plot_rego_eval_time_comparison()
        self.plot_action_time_statistics()
        self.plot_permission_time_statistics()
        self.plot_permission_mean_vs_default_allow()
        self.plot_average_time_three_modes()
        self.plot_action_mean_ratio()
        self.plot_baseline_relative_cost()

        print()
        print("Benchmark results written to:")
        print(self.output_dir)


if __name__ == "__main__":
    benchmark = OPABenchmark(
        mapping_aware_file=str(OUTPUT_MAPPING_AWARE_PATH),
        mapping_agnostic_file=str(OUTPUT_MAPPING_AGNOSTIC_PATH),
        default_allow_file=str(OUTPUT_DEFAULT_ALLOW_PATH),
        output_dir=str(OUTPUT_BENCHMARK_DIR),
    )

    benchmark.run()

    plot_permission_action_matrix(
        check_for_action_file=CHECK_FOR_ACTION_PATH,
        output_file="Analysis/output/action_permission_euler_v2.png"
    )