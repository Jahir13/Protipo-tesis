"""Script utilitario independiente para auditar la entropía de un dataset CSV de OTPs.

Puede ejecutarse directamente sobre `data/dataset_otp.csv` sin regenerar muestras:
    python evaluate_entropy.py --csv data/dataset_otp.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.metrics.entropy_analyzer import EntropyAnalyzer


def main(argv: list[str] | None = None) -> int:
    """Analiza un archivo CSV existente e imprime su reporte de entropía."""
    parser = argparse.ArgumentParser(
        prog="evaluate_entropy",
        description="Calcula la Entropía de Shannon (bits) y distribución de dígitos de un CSV de OTPs.",
    )
    parser.add_argument(
        "-c",
        "--csv",
        type=str,
        default="data/dataset_otp.csv",
        help="Ruta al archivo CSV de entrada (por defecto: data/dataset_otp.csv).",
    )
    args = parser.parse_args(argv)

    base_dir = Path(__file__).resolve().parent
    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = base_dir / csv_path

    try:
        report = EntropyAnalyzer.analyze_csv(csv_path)
        print(EntropyAnalyzer.format_console_report(report))
        return 0
    except (FileNotFoundError, KeyError, ValueError) as exc:
        print(f"[ERROR] No se pudo evaluar el archivo CSV: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

