import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt

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
        It is used to measure the http latency of the OPA request itself, without any evaluation.

    Logical test:
        (testId, repetition)

    For each logical test:
        - calls = number of executed OPA requests
        - timer_rego_query_eval_ns = time required to OPA to evaluate the Rego query
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
        """
        Mapping Aware already contains one row per logical test.
        """
        rows = []

        for result in self.mapping_aware:
            rows.append({
                "testId": result.get("testId"),
                "repetition": result.get("repetition"),
                "securityGroup": result.get("securityGroup"),
                "action": result.get("action"),
                "expectedAllowed": bool(result.get("expectedAllowed")),
                "decision": bool(result.get("opaActual")),
                "passed": result.get("matches") is True,
                "calls": 1,
                "total_timer_rego_query_eval_ns": self._ns(result.get("opaEvalNs")),
                "rows": [result],
            })

        return rows

    def _aggregate_default_allow(self) -> List[Dict[str, Any]]:
        """
        Default-allow is a baseline: every action request is allowed without
        authorization-policy evaluation. Its timer_rego_query_eval_ns is still measured.

        Each row represents one logical test (testId, repetition), just like
        Mapping Aware. The expected decision is intentionally not used to
        override the default-allow result.
        """
        rows = []

        for result in self.default_allow:
            rows.append({
                "testId": result.get("testId"),
                "repetition": result.get("repetition"),
                "securityGroup": result.get("securityGroup"),
                "action": result.get("action"),
                "expectedAllowed": bool(result.get("expectedAllowed")),
                "decision": True,
                "passed": result.get("matches") is True,
                "calls": 1 if result.get("opaEvalNs") is not None else 0,
                "total_timer_rego_query_eval_ns": self._ns(result.get("opaEvalNs")),
                "rows": [result],
            })

        return rows

    def _aggregate_mapping_agnostic(self) -> List[Dict[str, Any]]:
        """
        Aggregate all permission requests belonging to one logical test.

        IMPORTANT:
        - Sort by permissionIndex.
        - Ignore skipped rows with no timer_rego_query_eval_ns timing.
        - The first executed False is the logical DENY.
        - If no executed False exists, the logical result is ALLOW.
        - Total latency is the sum of executed permission requests.
        """
        groups: Dict[Tuple[Any, Any], List[Dict[str, Any]]] = {}

        for result in self.mapping_agnostic:
            key = self._test_key(result)
            groups.setdefault(key, []).append(result)

        aggregated = []

        for key, rows in groups.items():
            rows = sorted(
                rows,
                key=lambda r: (
                    r.get("permissionIndex")
                    if r.get("permissionIndex") is not None
                    else 10**9
                ),
            )

            executed = [r for r in rows if self._executed(r)]

            if not executed:
                # Keep the logical test visible, but it cannot be timed.
                expected = bool(rows[0].get("expectedAllowed"))
                decision = False
                total_latency = 0.0
                calls = 0
            else:
                expected = bool(executed[0].get("expectedAllowed"))

                first_denied = next(
                    (r for r in executed if r.get("opaActual") is False),
                    None,
                )

                if first_denied is not None:
                    decision = False
                else:
                    decision = True

                total_latency = sum(
                    self._ns(r.get("opaEvalNs"))
                    for r in executed
                )
                calls = len(executed)

            aggregated.append({
                "testId": key[0],
                "repetition": key[1],
                "securityGroup": rows[0].get("securityGroup"),
                "action": rows[0].get("action"),
                "expectedAllowed": expected,
                "decision": decision,
                "passed": decision == expected,
                "calls": calls,
                "total_timer_rego_query_eval_ns": total_latency,
                "rows": rows,
            })

        # Stable ordering: test first, repetition second.
        aggregated.sort(
            key=lambda r: (
                r["testId"] if r["testId"] is not None else 10**9,
                r["repetition"] if r["repetition"] is not None else 10**9,
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
        passed = sum(1 for t in tests if t["passed"])
        total = len(tests)

        times = [
            t["total_timer_rego_query_eval_ns"]
            for t in tests
            if t["calls"] > 0
        ]

        calls = [t["calls"] for t in tests]

        return {
            "logicalTests": total,
            "passedTests": passed,
            "failedTests": total - passed,
            "accuracy": passed / total if total else 0.0,
            "totalOpaExecutions": sum(calls),
            "averageCallsPerTest": statistics.mean(calls) if calls else 0.0,
            "minCalls": min(calls) if calls else 0,
            "maxCalls": max(calls) if calls else 0,
            "total_timer_rego_query_eval_ns": self._statistics(times),
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

        for test in tests:
            action = test.get("action") or "UNKNOWN"
            if test["calls"] == 0:
                continue
            grouped.setdefault(action, []).append(
                test["total_timer_rego_query_eval_ns"]
            )

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

        return {
            permission: {
                "count": len(values),
                "minNs": min(values),
                "avgNs": statistics.mean(values),
                "maxNs": max(values),
            }
            for permission, values in sorted(grouped.items())
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
        """
        One figure with three vertically aligned graphs:

        1. Number of OPA calls per logical test.
        2. Total timer_rego_query_eval_ns per logical test.
        3. Passed / failed per logical test.

        Mapping Aware and Mapping Agnostic use exactly the same x-axis positions.

        The x-axis label contains:
            testId/repetition
            action
        """
        mapping_aware, mapping_agnostic = self._paired_tests()

        if not mapping_aware and not mapping_agnostic:
            return

        mapping_aware_map = {
            self._test_key(t): t for t in mapping_aware
        }
        mapping_agnostic_map = {
            self._test_key(t): t for t in mapping_agnostic
        }

        keys = sorted(
            set(mapping_aware_map) | set(mapping_agnostic_map),
            key=lambda k: (
                k[0] if k[0] is not None else 10 ** 9,
                k[1] if k[1] is not None else 10 ** 9,
            ),
        )

        x = list(range(1, len(keys) + 1))

        mapping_aware_calls = [
            mapping_aware_map[k]["calls"] if k in mapping_aware_map else None
            for k in keys
        ]

        mapping_agnostic_calls = [
            mapping_agnostic_map[k]["calls"] if k in mapping_agnostic_map else None
            for k in keys
        ]

        mapping_aware_time = [
            (
                mapping_aware_map[k]["total_timer_rego_query_eval_ns"] / 1_000_000
                if k in mapping_aware_map
                else None
            )
            for k in keys
        ]

        mapping_agnostic_time = [
            (
                mapping_agnostic_map[k]["total_timer_rego_query_eval_ns"] / 1_000_000
                if k in mapping_agnostic_map
                else None
            )
            for k in keys
        ]

        mapping_aware_passed = [
            1 if mapping_aware_map[k]["passed"] else 0
            if k in mapping_aware_map
            else None
            for k in keys
        ]

        mapping_agnostic_passed = [
            1 if mapping_agnostic_map[k]["passed"] else 0
            if k in mapping_agnostic_map
            else None
            for k in keys
        ]

        fig, axes = plt.subplots(
            3,
            1,
            figsize=(16, 14),
            sharex=True,
        )

        # ------------------------------------------------------
        # Calls
        # ------------------------------------------------------
        axes[0].plot(
            x,
            mapping_aware_calls,
            marker="o",
            label="Mapping Aware",
        )

        axes[0].plot(
            x,
            mapping_agnostic_calls,
            marker="o",
            label="Mapping Agnostic",
        )

        axes[0].set_ylabel("OPA calls")
        axes[0].set_title("OPA Calls per Logical Test")
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)

        # ------------------------------------------------------
        # Total time
        # ------------------------------------------------------
        axes[1].plot(
            x,
            mapping_aware_time,
            marker="o",
            label="Mapping Aware",
        )

        axes[1].plot(
            x,
            mapping_agnostic_time,
            marker="o",
            label="Mapping Agnostic",
        )

        axes[1].set_ylabel("Total timer_rego_query_eval_ns (ms)")
        axes[1].set_title("Total OPA timer_rego_query_eval_ns per Logical Test")
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        # ------------------------------------------------------
        # Passed / failed
        # ------------------------------------------------------
        axes[2].plot(
            x,
            mapping_aware_passed,
            marker="o",
            label="Mapping Aware",
        )

        axes[2].plot(
            x,
            mapping_agnostic_passed,
            marker="o",
            label="Mapping Agnostic",
        )

        axes[2].set_yticks([0, 1])
        axes[2].set_yticklabels(["Failed", "Passed"])
        axes[2].set_ylabel("Result")
        axes[2].set_xlabel("Logical test")
        axes[2].set_title("Authorization Result")
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)

        axes[2].set_xticks(x)
        axes[2].set_xticklabels([""] * len(x))

        # Group repetitions by test ID.
        test_groups = {}
        for i, key in enumerate(keys):
            test_id, repetition = key
            test = mapping_aware_map.get(key) or mapping_agnostic_map.get(key)
            action = test.get("action", "UNKNOWN")

            if test_id not in test_groups:
                test_groups[test_id] = {
                    "positions": [],
                    "action": action,
                }

            test_groups[test_id]["positions"].append(x[i])

        # Add grouped labels below the x-axis.
        for test_id, group in test_groups.items():
            positions = group["positions"]
            center = (positions[0] + positions[-1]) / 2

            axes[2].text(
                center,
                -0.18,
                f"Test {test_id}\n{group['action']}",
                transform=axes[2].get_xaxis_transform(),
                ha="right",
                va="top",
                rotation=45,
                rotation_mode="anchor",
                fontsize=8,
            )

            # Separate groups visually.
            if positions[-1] < x[-1]:
                axes[2].axvline(
                    positions[-1] + 0.5,
                    color="gray",
                    linestyle=":",
                    alpha=0.5,
                )

        axes[2].set_xlabel("Logical tests (repetitions grouped by test ID)")
        axes[2].tick_params(axis="x", length=0)

        # Leave enough room for the grouped labels.
        fig.subplots_adjust(bottom=0.42)

        fig.tight_layout()

        output = self.output_dir / "test_comparison.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)


    # ==========================================================
    # ACTION STATISTICS GRAPH
    # ==========================================================

    def plot_action_time_statistics(self) -> None:
        """
        Mapping Aware vs Mapping Agnostic action total-time statistics.

        One subplot is created for each action.

        Inside each action subplot:
            - Min
            - Average
            - Max

        are represented as stacked columns.

        For every statistic there are two columns:
            Mapping Aware
            Mapping Agnostic

        The graph therefore allows direct comparison of Mapping Aware
        and Mapping Agnostic for every action and every statistic.
        """

        details = self.detailed_statistics()

        actions = sorted(
            set(details["mapping_awareByAction"])
            | set(details["mapping_agnosticByAction"])
        )

        if not actions:
            return

        # ------------------------------------------------------
        # Create one subplot for every action
        # ------------------------------------------------------

        n_actions = len(actions)

        fig, axes = plt.subplots(
            n_actions,
            1,
            figsize=(14, max(5, 4 * n_actions)),
            squeeze=False,
        )

        axes = axes.flatten()

        statistics_names = ["Min", "Average", "Max"]

        # ------------------------------------------------------
        # One subplot per action
        # ------------------------------------------------------

        for axis, action in zip(axes, actions):
            mapping_aware_data = details["mapping_awareByAction"].get(action)
            mapping_agnostic_data = details["mapping_agnosticByAction"].get(action)

            mapping_aware_values = [
                mapping_aware_data["minNs"] / 1_000_000
                if mapping_aware_data else 0,
                mapping_aware_data["avgNs"] / 1_000_000
                if mapping_aware_data else 0,
                mapping_aware_data["maxNs"] / 1_000_000
                if mapping_aware_data else 0,
            ]

            mapping_agnostic_values = [
                mapping_agnostic_data["minNs"] / 1_000_000
                if mapping_agnostic_data else 0,
                mapping_agnostic_data["avgNs"] / 1_000_000
                if mapping_agnostic_data else 0,
                mapping_agnostic_data["maxNs"] / 1_000_000
                if mapping_agnostic_data else 0,
            ]

            x = list(range(len(statistics_names)))

            width = 0.35

            # --------------------------------------------------
            # Mapping Aware stacked column
            # --------------------------------------------------

            axis.bar(
                [
                    value - width / 2
                    for value in x
                ],
                mapping_aware_values,
                width=width,
                label="Mapping Aware",
            )

            # --------------------------------------------------
            # Mapping Agnostic stacked column
            # --------------------------------------------------

            axis.bar(
                [
                    value + width / 2
                    for value in x
                ],
                mapping_agnostic_values,
                width=width,
                label="Mapping Agnostic",
            )

            # --------------------------------------------------
            # Formatting
            # --------------------------------------------------

            axis.set_xticks(x)
            axis.set_xticklabels(statistics_names)

            axis.set_ylabel("Time (ms)")
            axis.set_title(action)

            axis.grid(
                True,
                axis="y",
                alpha=0.3,
            )

            axis.legend()

        fig.suptitle(
            "Mapping Aware vs Mapping Agnostic — Total timer_rego_query_eval_ns Time by Action",
            fontsize=16,
        )

        fig.supxlabel("Statistic")

        fig.tight_layout(
            rect=(0, 0, 1, 0.97)
        )

        output = self.output_dir / "action_time_statistics.png"

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
        Compare average total timer_rego_query_eval_ns per logical action test for:
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
        ax.set_ylabel("Average timer_rego_query_eval_ns (ms)")
        ax.set_title("Average OPA timer_rego_query_eval_ns by Action — Three Authorization Modes")
        ax.grid(True, axis="y", alpha=0.3)
        ax.legend()
        fig.tight_layout()

        output = self.output_dir / "average_time_three_modes.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)

    # ==========================================================
    # PERMISSION STATISTICS GRAPH
    # ==========================================================

    def plot_permission_time_statistics(self) -> None:
        """
        Mapping Agnostic permission-level min / average / max timer_rego_query_eval_ns.

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
            "Mapping Agnostic — Min / Average / Max timer_rego_query_eval_ns by Permission"
        )

        ax.grid(
            True,
            alpha=0.3,
        )

        ax.legend()

        fig.tight_layout()

        output = self.output_dir / "permission_time_statistics.png"

        fig.savefig(
            output,
            dpi=300,
            bbox_inches="tight",
        )

        plt.close(fig)



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
        self.plot_action_time_statistics()
        self.plot_permission_time_statistics()
        self.plot_average_time_three_modes()

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
        output_file="Analysis/output/action_permission_euler.png"
    )

