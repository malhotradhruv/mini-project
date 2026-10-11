"""Unit tests for Academic Benchmark Runner in src/evaluation/benchmark_runner.py.

Conforms to IEEE Access (Hmimou et al., 2025):
"A Multi-Agent System for Cybersecurity Threat Detection and Correlation Using Large Language Models"
"""

import os
import json
import pytest
from src.evaluation.benchmark_runner import AcademicBenchmarkSuite


@pytest.fixture
def benchmark_suite(tmp_path):
    output_file = str(tmp_path / "benchmark_test_results.json")
    return AcademicBenchmarkSuite(output_path=output_file)


class TestAcademicBenchmarkSuite:
    def test_corpus_size_and_composition(self, benchmark_suite):
        cases = benchmark_suite.load_test_cases()
        assert len(cases) == 30

        email_cases = [c for c in cases if c["type"] == "email"]
        log_cases = [c for c in cases if c["type"] == "log"]
        multi_cases = [c for c in cases if c["type"] == "multi_vector"]

        assert len(email_cases) == 10
        assert len(log_cases) == 10
        assert len(multi_cases) == 10

    def test_corpus_ground_truth_balance(self, benchmark_suite):
        cases = benchmark_suite.load_test_cases()
        malicious = [c for c in cases if c["ground_truth_malicious"]]
        benign = [c for c in cases if not c["ground_truth_malicious"]]

        # 15 malicious (5 phish + 5 mal logs + 5 breach) and 15 benign (5 ham + 5 benign logs + 5 benign multi)
        assert len(malicious) == 15
        assert len(benign) == 15

        correlated = [c for c in cases if c["ground_truth_correlated"]]
        assert len(correlated) == 5

    def test_report_formatting(self, benchmark_suite, capsys):
        mock_results = {
            "metrics": {
                "system_accuracy": 94.2,
                "threat_correlation_precision": 89.1,
                "precision": 92.0,
                "recall": 95.0,
                "f1_score": 0.935,
                "false_positive_rate": 6.7,
                "analyst_time_reduction": 40.5,
            },
            "confusion_matrix": {"tp": 14, "fp": 1, "tn": 14, "fn": 1},
            "correlation_matrix": {"corr_tp": 5, "corr_fp": 0, "corr_tn": 5, "corr_fn": 0},
            "total_execution_seconds": 45.2,
        }

        benchmark_suite.print_academic_report(mock_results)
        captured = capsys.readouterr()
        assert "ACADEMIC EVALUATION & BENCHMARK COMPARISON REPORT" in captured.out
        assert "System-Wide Accuracy" in captured.out
        assert "94.2%" in captured.out
