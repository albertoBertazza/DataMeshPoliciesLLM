import json
import statistics
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt

from Pipelines.costantPath import OUTPUT_STATEFUL_PATH, OUTPUT_STATELESS_PATH, OUTPUT_BENCHMARK_DIR


# ==============================================================
# BENCHMARK
# ==============================================================

class OPABenchmark:
    """
    Analyze the results produced by the stateful and stateless
    OPA analysis.

    The benchmark compares:

        Stateful:
            action -> one OPA request

        Stateless:
            action -> permission 1 -> permission 2 -> ...
            until a permission fails or all permissions succeed.

    Metrics:

        - number of logical tests
        - number of OPA executions
        - correct decisions
        - mismatches
        - accuracy
        - HTTP latency
        - OPA evaluation time
        - OPA compilation time
        - OPA handler time
        - latency percentiles
        - executions per logical test
    """

    # ==========================================================
    # INIT
    # ==========================================================

    def __init__(
        self,
        stateful_file: str | Path,
        stateless_file: str | Path,
        output_dir: str | Path,
    ):
        self.stateful_file = Path(stateful_file)
        self.stateless_file = Path(stateless_file)
        self.output_dir = Path(output_dir)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.stateful = self._load(
            self.stateful_file
        )

        self.stateless = self._load(
            self.stateless_file
        )

    # ==========================================================
    # LOAD
    # ==========================================================

    @staticmethod
    def _load(
        path: Path,
    ) -> List[Dict[str, Any]]:

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):
            raise ValueError(
                f"Benchmark file must contain a JSON list: {path}"
            )

        return data

    # ==========================================================
    # NUMERIC VALUES
    # ==========================================================

    @staticmethod
    def _values(
        results: List[Dict[str, Any]],
        field: str,
    ) -> List[float]:

        values = []

        for result in results:

            value = result.get(field)

            if value is None:
                continue

            try:
                values.append(float(value))

            except (
                TypeError,
                ValueError,
            ):
                continue

        return values

    # ==========================================================
    # PERCENTILE
    # ==========================================================

    @staticmethod
    def _percentile(
        values: List[float],
        percentile: float,
    ) -> Optional[float]:

        if not values:
            return None

        values = sorted(values)

        if len(values) == 1:
            return values[0]

        position = (
            percentile / 100
        ) * (len(values) - 1)

        lower = int(position)
        upper = lower + 1

        if upper >= len(values):
            return values[-1]

        weight = position - lower

        return (
            values[lower]
            + weight
            * (
                values[upper]
                - values[lower]
            )
        )

    # ==========================================================
    # STATISTICS
    # ==========================================================

    def _statistics(
        self,
        values: List[float],
    ) -> Dict[str, Optional[float]]:

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
            "p95": self._percentile(
                values,
                95,
            ),
            "p99": self._percentile(
                values,
                99,
            ),
            "min": min(values),
            "max": max(values),
        }

    # ==========================================================
    # LOGICAL TESTS
    # ==========================================================

    @staticmethod
    def _logical_tests(
        results: List[Dict[str, Any]],
    ) -> int:

        return len({
            result.get("testId")
            for result in results
            if result.get("testId") is not None
        })

    # ==========================================================
    # BASIC METRICS
    # ==========================================================

    def _basic_metrics(
        self,
        results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        executions = len(results)

        correct = sum(
            1
            for result in results
            if result.get("matches") is True
        )

        mismatches = (
            executions - correct
        )

        accuracy = (
            correct / executions
            if executions
            else 0.0
        )

        logical_tests = (
            self._logical_tests(results)
        )

        executions_per_test = (
            executions / logical_tests
            if logical_tests
            else 0.0
        )

        return {
            "logicalTests": logical_tests,
            "opaExecutions": executions,
            "correctDecisions": correct,
            "mismatches": mismatches,
            "accuracy": accuracy,
            "executionsPerLogicalTest": (
                executions_per_test
            ),
        }

    # ==========================================================
    # COMPLETE METRICS
    # ==========================================================

    def _calculate_metrics(
        self,
        results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        metrics = self._basic_metrics(
            results
        )

        # ------------------------------------------------------
        # Latency
        # ------------------------------------------------------

        http_latency = self._values(
            results,
            "httpLatencyNs",
        )

        opa_eval = self._values(
            results,
            "opaEvalNs",
        )

        opa_compile = self._values(
            results,
            "opaCompileNs",
        )

        opa_handler = self._values(
            results,
            "opaHandlerNs",
        )

        metrics["httpLatencyNs"] = (
            self._statistics(
                http_latency
            )
        )

        metrics["opaEvalNs"] = (
            self._statistics(
                opa_eval
            )
        )

        metrics["opaCompileNs"] = (
            self._statistics(
                opa_compile
            )
        )

        metrics["opaHandlerNs"] = (
            self._statistics(
                opa_handler
            )
        )

        return metrics

    # ==========================================================
    # PUBLIC SUMMARY
    # ==========================================================

    def summary(self) -> Dict[str, Any]:

        return {
            "stateful": self._calculate_metrics(
                self.stateful
            ),
            "stateless": self._calculate_metrics(
                self.stateless
            ),
        }

    # ==========================================================
    # PRINT SUMMARY
    # ==========================================================

    def print_summary(self) -> None:

        summary = self.summary()

        print()
        print("=" * 80)
        print("OPA BENCHMARK")
        print("=" * 80)

        for mode in (
            "stateful",
            "stateless",
        ):

            metrics = summary[mode]

            print()
            print(
                f"{mode.upper()}"
            )
            print("-" * 80)

            print(
                f"Logical tests:          "
                f"{metrics['logicalTests']}"
            )

            print(
                f"OPA executions:         "
                f"{metrics['opaExecutions']}"
            )

            print(
                f"Correct decisions:      "
                f"{metrics['correctDecisions']}"
            )

            print(
                f"Mismatches:             "
                f"{metrics['mismatches']}"
            )

            print(
                f"Accuracy:               "
                f"{metrics['accuracy']:.2%}"
            )

            print(
                f"Executions/test:        "
                f"{metrics['executionsPerLogicalTest']:.2f}"
            )

            # --------------------------------------------------
            # HTTP
            # --------------------------------------------------

            http = metrics[
                "httpLatencyNs"
            ]

            print()
            print("HTTP latency:")

            print(
                f"  Mean:                 "
                f"{self._format_ns(http['mean'])}"
            )

            print(
                f"  Median:               "
                f"{self._format_ns(http['median'])}"
            )

            print(
                f"  P95:                  "
                f"{self._format_ns(http['p95'])}"
            )

            print(
                f"  P99:                  "
                f"{self._format_ns(http['p99'])}"
            )

            # --------------------------------------------------
            # OPA evaluation
            # --------------------------------------------------

            evaluation = metrics[
                "opaEvalNs"
            ]

            print()
            print("OPA evaluation:")

            print(
                f"  Mean:                 "
                f"{self._format_ns(evaluation['mean'])}"
            )

            print(
                f"  Median:               "
                f"{self._format_ns(evaluation['median'])}"
            )

            print(
                f"  P95:                  "
                f"{self._format_ns(evaluation['p95'])}"
            )

            # --------------------------------------------------
            # Handler
            # --------------------------------------------------

            handler = metrics[
                "opaHandlerNs"
            ]

            print()
            print("OPA handler:")

            print(
                f"  Mean:                 "
                f"{self._format_ns(handler['mean'])}"
            )

    # ==========================================================
    # FORMAT
    # ==========================================================

    @staticmethod
    def _format_ns(
        value: Optional[float],
    ) -> str:

        if value is None:
            return "N/A"

        if value >= 1_000_000:

            return (
                f"{value / 1_000_000:.3f} ms"
            )

        if value >= 1_000:

            return (
                f"{value / 1_000:.3f} µs"
            )

        return f"{value:.0f} ns"

    # ==========================================================
    # GRAPH 1
    # LATENCY
    # ==========================================================

    def plot_latency(
        self,
        field: str = "httpLatencyNs",
        title: str = "OPA HTTP Latency",
    ) -> None:

        stateful = self._values(
            self.stateful,
            field,
        )

        stateless = self._values(
            self.stateless,
            field,
        )

        if not stateful and not stateless:
            return

        plt.figure(
            figsize=(10, 6)
        )

        if stateful:
            plt.plot(
                range(1, len(stateful) + 1),
                [
                    x / 1_000_000
                    for x in stateful
                ],
                label="Stateful",
            )

        if stateless:
            plt.plot(
                range(1, len(stateless) + 1),
                [
                    x / 1_000_000
                    for x in stateless
                ],
                label="Stateless",
            )

        plt.xlabel(
            "OPA execution"
        )

        plt.ylabel(
            "Latency (ms)"
        )

        plt.title(title)

        plt.legend()

        plt.grid(
            True,
            alpha=0.3,
        )

        plt.tight_layout()

        output = (
            self.output_dir
            / f"{field}_comparison.png"
        )

        plt.savefig(
            output,
            dpi=300,
        )

        plt.close()

    # ==========================================================
    # GRAPH 2
    # LATENCY DISTRIBUTION
    # ==========================================================

    def plot_latency_distribution(
        self,
    ) -> None:

        stateful = [
            x / 1_000_000
            for x in self._values(
                self.stateful,
                "httpLatencyNs",
            )
        ]

        stateless = [
            x / 1_000_000
            for x in self._values(
                self.stateless,
                "httpLatencyNs",
            )
        ]

        if not stateful and not stateless:
            return

        plt.figure(
            figsize=(10, 6)
        )

        plt.boxplot(
            [
                stateful,
                stateless,
            ],
            tick_labels=[
                "Stateful",
                "Stateless",
            ],
        )

        plt.ylabel(
            "HTTP latency (ms)"
        )

        plt.title(
            "OPA HTTP Latency Distribution"
        )

        plt.grid(
            True,
            axis="y",
            alpha=0.3,
        )

        plt.tight_layout()

        output = (
            self.output_dir
            / "latency_distribution.png"
        )

        plt.savefig(
            output,
            dpi=300,
        )

        plt.close()

    # ==========================================================
    # GRAPH 3
    # OPA INTERNAL TIMES
    # ==========================================================

    def plot_internal_metrics(
        self,
    ) -> None:

        metric_fields = {
            "OPA evaluation": "opaEvalNs",
            "OPA compilation": "opaCompileNs",
            "OPA handler": "opaHandlerNs",
        }

        stateful_means = []
        stateless_means = []
        labels = []

        for label, field in metric_fields.items():

            stateful = self._values(
                self.stateful,
                field,
            )

            stateless = self._values(
                self.stateless,
                field,
            )

            if not stateful and not stateless:
                continue

            labels.append(label)

            stateful_means.append(
                statistics.mean(
                    stateful
                ) / 1_000_000
                if stateful
                else 0
            )

            stateless_means.append(
                statistics.mean(
                    stateless
                ) / 1_000_000
                if stateless
                else 0
            )

        if not labels:
            return

        x = range(len(labels))

        width = 0.35

        plt.figure(
            figsize=(10, 6)
        )

        plt.bar(
            [
                i - width / 2
                for i in x
            ],
            stateful_means,
            width,
            label="Stateful",
        )

        plt.bar(
            [
                i + width / 2
                for i in x
            ],
            stateless_means,
            width,
            label="Stateless",
        )

        plt.xticks(
            list(x),
            labels,
            rotation=20,
        )

        plt.ylabel(
            "Mean time (ms)"
        )

        plt.title(
            "OPA Internal Performance"
        )

        plt.legend()

        plt.grid(
            True,
            axis="y",
            alpha=0.3,
        )

        plt.tight_layout()

        output = (
            self.output_dir
            / "internal_metrics.png"
        )

        plt.savefig(
            output,
            dpi=300,
        )

        plt.close()

    # ==========================================================
    # GRAPH 4
    # CORRECTNESS
    # ==========================================================

    def plot_correctness(
        self,
    ) -> None:

        stateful = self._basic_metrics(
            self.stateful
        )

        stateless = self._basic_metrics(
            self.stateless
        )

        labels = [
            "Stateful",
            "Stateless",
        ]

        correct = [
            stateful["correctDecisions"],
            stateless["correctDecisions"],
        ]

        mismatches = [
            stateful["mismatches"],
            stateless["mismatches"],
        ]

        x = range(
            len(labels)
        )

        width = 0.35

        plt.figure(
            figsize=(9, 6)
        )

        plt.bar(
            [
                i - width / 2
                for i in x
            ],
            correct,
            width,
            label="Correct",
        )

        plt.bar(
            [
                i + width / 2
                for i in x
            ],
            mismatches,
            width,
            label="Mismatch",
        )

        plt.xticks(
            list(x),
            labels,
        )

        plt.ylabel(
            "Number of executions"
        )

        plt.title(
            "Authorization Correctness"
        )

        plt.legend()

        plt.grid(
            True,
            axis="y",
            alpha=0.3,
        )

        plt.tight_layout()

        output = (
            self.output_dir
            / "correctness.png"
        )

        plt.savefig(
            output,
            dpi=300,
        )

        plt.close()

    # ==========================================================
    # GRAPH 5
    # EXECUTIONS PER LOGICAL TEST
    # ==========================================================

    def plot_execution_overhead(
        self,
    ) -> None:

        stateful = self._basic_metrics(
            self.stateful
        )

        stateless = self._basic_metrics(
            self.stateless
        )

        labels = [
            "Stateful",
            "Stateless",
        ]

        values = [
            stateful[
                "executionsPerLogicalTest"
            ],
            stateless[
                "executionsPerLogicalTest"
            ],
        ]

        plt.figure(
            figsize=(8, 6)
        )

        plt.bar(
            labels,
            values,
        )

        plt.ylabel(
            "OPA executions / logical test"
        )

        plt.title(
            "Authorization Execution Overhead"
        )

        plt.grid(
            True,
            axis="y",
            alpha=0.3,
        )

        plt.tight_layout()

        output = (
            self.output_dir
            / "execution_overhead.png"
        )

        plt.savefig(
            output,
            dpi=300,
        )

        plt.close()

    # ==========================================================
    # SAVE SUMMARY
    # ==========================================================

    def save_summary(
        self,
    ) -> Path:

        summary = self.summary()

        output = (
            self.output_dir
            / "benchmark_summary.json"
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                summary,
                file,
                indent=2,
            )

        return output

    # ==========================================================
    # RUN EVERYTHING
    # ==========================================================

    def run(self) -> None:

        self.print_summary()

        self.save_summary()

        self.plot_latency()

        self.plot_latency_distribution()

        self.plot_internal_metrics()

        self.plot_correctness()

        self.plot_execution_overhead()

        print()
        print(
            f"Benchmark results written to:"
        )
        print(
            self.output_dir
        )


# ==============================================================
# MAIN
# ==============================================================

if __name__ == "__main__":

    benchmark = OPABenchmark(
        stateful_file=(str(OUTPUT_STATEFUL_PATH)),
        stateless_file=(str(OUTPUT_STATELESS_PATH)),
        output_dir=(str(OUTPUT_BENCHMARK_DIR))
    )

    benchmark.run()
