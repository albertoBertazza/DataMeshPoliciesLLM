
import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib.pyplot as plt

from DrawGraph.draw_permission_in_action import plot_action_permission_euler
from Pipelines.costantPath import (
    OUTPUT_STATEFUL_PATH,
    OUTPUT_STATELESS_PATH,
    OUTPUT_BENCHMARK_DIR,
)


class OPABenchmark:
    """
    Benchmark Stateful vs Stateless authorization.

    Stateful:
        One OPA request for the complete action.

    Stateless:
        One OPA request per required permission.
        Evaluation short-circuits at the first denied permission.

    Logical test:
        (testId, repetition)

    For each logical test:
        - calls = number of executed OPA requests
        - total HTTP time = sum of executed OPA request times
        - decision = DENY if the first executed denied permission is found;
                     otherwise ALLOW
        - passed = final decision == expectedAllowed

    This makes Stateful and Stateless directly comparable at the same
    x-axis position.
    """

    def __init__(
        self,
        stateful_file: str | Path,
        stateless_file: str | Path,
        output_dir: str | Path,
    ):
        self.stateful_file = Path(stateful_file)
        self.stateless_file = Path(stateless_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.stateful = self._load(self.stateful_file)
        self.stateless = self._load(self.stateless_file)

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
        A stateless row is an executed OPA request when it has timing data.

        This also handles explicitly skipped rows produced by the runner:
        skipped rows have no HTTP timing.
        """
        return result.get("httpLatencyNs") is not None

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

    def _aggregate_stateful(self) -> List[Dict[str, Any]]:
        """
        Stateful already contains one row per logical test.
        """
        rows = []

        for result in self.stateful:
            rows.append({
                "testId": result.get("testId"),
                "repetition": result.get("repetition"),
                "securityGroup": result.get("securityGroup"),
                "action": result.get("action"),
                "expectedAllowed": bool(result.get("expectedAllowed")),
                "decision": bool(result.get("opaActual")),
                "passed": result.get("matches") is True,
                "calls": 1,
                "totalHttpLatencyNs": self._ns(result.get("httpLatencyNs")),
                "rows": [result],
            })

        return rows

    def _aggregate_stateless(self) -> List[Dict[str, Any]]:
        """
        Aggregate all permission requests belonging to one logical test.

        IMPORTANT:
        - Sort by permissionIndex.
        - Ignore skipped rows with no HTTP timing.
        - The first executed False is the logical DENY.
        - If no executed False exists, the logical result is ALLOW.
        - Total latency is the sum of executed permission requests.
        """
        groups: Dict[Tuple[Any, Any], List[Dict[str, Any]]] = {}

        for result in self.stateless:
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
                    self._ns(r.get("httpLatencyNs"))
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
                "totalHttpLatencyNs": total_latency,
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
        Put Stateful and Stateless logical tests in the same x-axis order.

        Pairing is done by (testId, repetition).
        """
        stateful = {
            self._test_key(row): row
            for row in self._aggregate_stateful()
        }
        stateless = {
            self._test_key(row): row
            for row in self._aggregate_stateless()
        }

        keys = sorted(
            set(stateful) | set(stateless),
            key=lambda k: (
                k[0] if k[0] is not None else 10**9,
                k[1] if k[1] is not None else 10**9,
            ),
        )

        return (
            [stateful[k] for k in keys if k in stateful],
            [stateless[k] for k in keys if k in stateless],
        )

    # ==========================================================
    # SUMMARY
    # ==========================================================

    def _mode_summary(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        passed = sum(1 for t in tests if t["passed"])
        total = len(tests)

        times = [
            t["totalHttpLatencyNs"]
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
            "totalHttpLatencyNs": self._statistics(times),
        }

    def summary(self) -> Dict[str, Any]:
        stateful = self._aggregate_stateful()
        stateless = self._aggregate_stateless()

        return {
            "stateful": self._mode_summary(stateful),
            "stateless": self._mode_summary(stateless),
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
                test["totalHttpLatencyNs"]
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
        Stateless permission-level min / average / max HTTP latency.

        Skipped permissions are excluded because they did not execute.
        """
        grouped: Dict[str, List[float]] = {}

        for result in self.stateless:
            if not self._executed(result):
                continue

            permission = result.get("operation") or "UNKNOWN"
            grouped.setdefault(permission, []).append(
                self._ns(result.get("httpLatencyNs"))
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
        stateful = self._aggregate_stateful()
        stateless = self._aggregate_stateless()

        return {
            "statefulByAction": self._action_statistics(stateful),
            "statelessByAction": self._action_statistics(stateless),
            "statelessByPermission": self._permission_statistics(),
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

        for mode in ("stateful", "stateless"):
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

            latency = m["totalHttpLatencyNs"]
            print()
            print("Total HTTP time per logical test:")
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
            "STATEFUL — TOTAL TIME BY ACTION",
            details["statefulByAction"],
        )
        print_table(
            "STATELESS — TOTAL TIME BY ACTION",
            details["statelessByAction"],
        )
        print_table(
            "STATELESS — TIME BY PERMISSION",
            details["statelessByPermission"],
        )


    # ==========================================================
    # GRAPH 1 + 2 + 3
    # ==========================================================

    def plot_test_comparison(self) -> None:
        """
        One figure with three vertically aligned graphs:

        1. Number of OPA calls per logical test.
        2. Total HTTP time per logical test.
        3. Passed / failed per logical test.

        Stateful and Stateless use exactly the same x-axis positions.

        The x-axis label contains:
            testId/repetition
            action
        """
        stateful, stateless = self._paired_tests()

        if not stateful and not stateless:
            return

        stateful_map = {
            self._test_key(t): t for t in stateful
        }
        stateless_map = {
            self._test_key(t): t for t in stateless
        }

        keys = sorted(
            set(stateful_map) | set(stateless_map),
            key=lambda k: (
                k[0] if k[0] is not None else 10 ** 9,
                k[1] if k[1] is not None else 10 ** 9,
            ),
        )

        x = list(range(1, len(keys) + 1))

        stateful_calls = [
            stateful_map[k]["calls"] if k in stateful_map else None
            for k in keys
        ]

        stateless_calls = [
            stateless_map[k]["calls"] if k in stateless_map else None
            for k in keys
        ]

        stateful_time = [
            (
                stateful_map[k]["totalHttpLatencyNs"] / 1_000_000
                if k in stateful_map
                else None
            )
            for k in keys
        ]

        stateless_time = [
            (
                stateless_map[k]["totalHttpLatencyNs"] / 1_000_000
                if k in stateless_map
                else None
            )
            for k in keys
        ]

        stateful_passed = [
            1 if stateful_map[k]["passed"] else 0
            if k in stateful_map
            else None
            for k in keys
        ]

        stateless_passed = [
            1 if stateless_map[k]["passed"] else 0
            if k in stateless_map
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
            stateful_calls,
            marker="o",
            label="Stateful",
        )

        axes[0].plot(
            x,
            stateless_calls,
            marker="o",
            label="Stateless",
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
            stateful_time,
            marker="o",
            label="Stateful",
        )

        axes[1].plot(
            x,
            stateless_time,
            marker="o",
            label="Stateless",
        )

        axes[1].set_ylabel("Total HTTP time (ms)")
        axes[1].set_title("Total OPA HTTP Time per Logical Test")
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        # ------------------------------------------------------
        # Passed / failed
        # ------------------------------------------------------
        axes[2].plot(
            x,
            stateful_passed,
            marker="o",
            label="Stateful",
        )

        axes[2].plot(
            x,
            stateless_passed,
            marker="o",
            label="Stateless",
        )

        axes[2].set_yticks([0, 1])
        axes[2].set_yticklabels(["Failed", "Passed"])
        axes[2].set_ylabel("Result")
        axes[2].set_xlabel("Logical test")
        axes[2].set_title("Authorization Result")
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)

        axes[2].set_xticks(x)

        # Add ACTION to every test label.
        labels = []

        for key in keys:
            test_id, repetition = key

            test = (
                    stateful_map.get(key)
                    or stateless_map.get(key)
            )

            action = test.get("action", "UNKNOWN")

            labels.append(
                f"{test_id}/{repetition}\n{action}"
            )

        axes[2].set_xticklabels(
            labels,
            rotation=45,
            ha="right",
        )

        fig.tight_layout()

        output = self.output_dir / "test_comparison.png"
        fig.savefig(output, dpi=300, bbox_inches="tight")
        plt.close(fig)


    # ==========================================================
    # ACTION STATISTICS GRAPH
    # ==========================================================

    def plot_action_time_statistics(self) -> None:
        """
        Stateful vs Stateless action total-time statistics.

        One subplot is created for each action.

        Inside each action subplot:
            - Min
            - Average
            - Max

        are represented as stacked columns.

        For every statistic there are two columns:
            Stateful
            Stateless

        The graph therefore allows direct comparison of Stateful
        and Stateless for every action and every statistic.
        """

        details = self.detailed_statistics()

        actions = sorted(
            set(details["statefulByAction"])
            | set(details["statelessByAction"])
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
            stateful_data = details["statefulByAction"].get(action)
            stateless_data = details["statelessByAction"].get(action)

            stateful_values = [
                stateful_data["minNs"] / 1_000_000
                if stateful_data else 0,
                stateful_data["avgNs"] / 1_000_000
                if stateful_data else 0,
                stateful_data["maxNs"] / 1_000_000
                if stateful_data else 0,
            ]

            stateless_values = [
                stateless_data["minNs"] / 1_000_000
                if stateless_data else 0,
                stateless_data["avgNs"] / 1_000_000
                if stateless_data else 0,
                stateless_data["maxNs"] / 1_000_000
                if stateless_data else 0,
            ]

            x = list(range(len(statistics_names)))

            width = 0.35

            # --------------------------------------------------
            # Stateful stacked column
            # --------------------------------------------------

            axis.bar(
                [
                    value - width / 2
                    for value in x
                ],
                stateful_values,
                width=width,
                label="Stateful",
            )

            # --------------------------------------------------
            # Stateless stacked column
            # --------------------------------------------------

            axis.bar(
                [
                    value + width / 2
                    for value in x
                ],
                stateless_values,
                width=width,
                label="Stateless",
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
            "Stateful vs Stateless — Total HTTP Time by Action",
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
    # PERMISSION STATISTICS GRAPH
    # ==========================================================

    def plot_permission_time_statistics(self) -> None:
        """
        Stateless permission-level min / average / max HTTP latency.

        All statistics are merged into one line chart.

        X-axis:
            Permission

        Lines:
            Minimum
            Average
            Maximum
        """

        data = self.detailed_statistics()["statelessByPermission"]

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
        ax.set_ylabel("HTTP time (ms)")

        ax.set_title(
            "Stateless — Min / Average / Max HTTP Time by Permission"
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

        print()
        print("Benchmark results written to:")
        print(self.output_dir)


if __name__ == "__main__":
    benchmark = OPABenchmark(
        stateful_file=str(OUTPUT_STATEFUL_PATH),
        stateless_file=str(OUTPUT_STATELESS_PATH),
        output_dir=str(OUTPUT_BENCHMARK_DIR),
    )

    benchmark.run()

    plot_action_permission_euler(
        "Analysis/docker-opa-stateful/opa/checkForAction.json",
        actions=[
            "AddColumnAction",
            "CreateMaterializedViewAction",
            "CreateSchemaAction",
            "CreateTableAction",
            "CreateViewAction",
            "SelectFromTableAction",
            "DeleteFromTableAction",
            "DropColumnAction",

        ],
        output_file="Analysis/output/action_permission_euler.png",
    )
