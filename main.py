"""Punto de entrada principal (CLI) del Módulo Evaluador de OTPs.

Orquesta la generación de códigos OTP vulnerables (CWE-330), el cálculo
preliminar de métricas de entropía de Shannon y la exportación del dataset
CSV (`data/dataset_otp.csv`) y su manifiesto JSON (`data/manifest.json`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.exporters.dataset_exporter import DatasetExporter
from src.generators.factory import OTPGeneratorFactory
from src.generators.python_random_generator import PythonRandomRandintGenerator
from src.metrics.entropy_analyzer import EntropyAnalyzer


def build_arg_parser() -> argparse.ArgumentParser:
    """Construye el analizador de argumentos de línea de comandos (CLI)."""
    parser = argparse.ArgumentParser(
        prog="otp_evaluator",
        description=(
            "Prototipo Evaluador de Entropía y Generador de Tokens OTP Inseguros "
            "(CWE-330: Use of Insufficiently Random Values)."
        ),
    )
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=100,
        help="Cantidad de tokens OTP a generar (por defecto: 100).",
    )
    parser.add_argument(
        "-d",
        "--digits",
        type=int,
        default=4,
        help="Longitud en dígitos de cada código OTP (por defecto: 4).",
    )
    parser.add_argument(
        "-s",
        "--seed",
        type=int,
        default=None,
        help=(
            "Semilla entera fija. Si se omite, se inicializa con el timestamp "
            "UNIX actual (int(time.time())) y queda registrado en el manifiesto."
        ),
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        type=str,
        default=PythonRandomRandintGenerator.ALGORITHM_ID,
        choices=OTPGeneratorFactory.available_algorithms(),
        help="Identificador del algoritmo PRNG a utilizar (por defecto: python_random_randint).",
    )
    parser.add_argument(
        "--csv-out",
        type=str,
        default="data/dataset_otp.csv",
        help="Ruta de salida para el archivo CSV (por defecto: data/dataset_otp.csv).",
    )
    parser.add_argument(
        "--manifest-out",
        type=str,
        default="data/manifest.json",
        help="Ruta de salida para el manifiesto JSON (por defecto: data/manifest.json).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Ejecuta el flujo completo del rol Evaluador.

    Args:
        argv: Lista de argumentos opcional (usa sys.argv si es None).

    Returns:
        Código de salida del proceso (0 si fue exitoso, 1 en caso de error).
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        # 1. Instanciar generador mediante Factory + Strategy
        generator = OTPGeneratorFactory.create(
            algorithm_id=args.algorithm,
            digits=args.digits,
            seed=args.seed,
        )

        # 2. Generar el lote de códigos OTP
        records = generator.generate_batch(count=args.count)
        tokens = [rec.otp for rec in records]

        # 3. Calcular métricas de Entropía de Shannon y frecuencias de dígitos
        entropy_report = EntropyAnalyzer.analyze_tokens(tokens)

        # 4. Exportar Dataset CSV y Manifiesto JSON
        base_dir = Path(__file__).resolve().parent
        csv_path = base_dir / args.csv_out
        manifest_path = base_dir / args.manifest_out

        exported_csv = DatasetExporter.export_csv(records=records, csv_path=csv_path)
        exported_manifest = DatasetExporter.export_manifest(
            generator=generator,
            records=records,
            csv_path=exported_csv,
            manifest_path=manifest_path,
            entropy_report=entropy_report,
        )

        # 5. Mostrar reporte en consola
        print(EntropyAnalyzer.format_console_report(entropy_report))
        print(f" [OK] Algoritmo empleado : {generator.algorithm_name}")
        print(f" [OK] Semilla utilizada  : {generator.seed} (visible para auditoria)")
        print(f" [OK] Dataset exportado  : {exported_csv}")
        print(f" [OK] Manifiesto JSON    : {exported_manifest}")
        print("=" * 68)
        return 0

    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"[ERROR] Fallo en la ejecucion del modulo Evaluador: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

