from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.generators.base import OTPGeneratorStrategy, OTPRecord
from src.metrics.entropy_analyzer import EntropyReport


class DatasetExporter:
    """Gestiona la persistencia en disco del dataset CSV y su manifiesto JSON."""

    CSV_COLUMNS: tuple[str, str, str] = ("id", "timestamp", "otp")

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Calcula el resumen criptográfico SHA-256 de un archivo en disco.

        Args:
            file_path: Ruta al archivo cuyo hash se desea calcular.

        Returns:
            Cadena hexadecimal con el digest SHA-256.
        """
        sha256_hash = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    @classmethod
    def export_csv(
        cls,
        records: list[OTPRecord],
        csv_path: str | Path,
    ) -> Path:
        """Exporta la lista de registros OTP al archivo CSV requerido por el Predictor.

        Crea automáticamente los directorios padres si no existen. Garantiza que
        la columna `otp` se escriba como cadena con ceros a la izquierda intactos.

        Args:
            records: Lista de registros OTPRecord generados.
            csv_path: Ruta de destino del archivo CSV (ej. `data/dataset_otp.csv`).

        Returns:
            Objeto Path resuelto del archivo CSV creado.

        Raises:
            ValueError: Si la lista de registros está vacía.
            OSError: Si ocurre un problema de permisos o escritura en disco.
        """
        if not records:
            raise ValueError("No se puede exportar un dataset vacío.")

        target_path = Path(csv_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        with target_path.open(mode="w", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(cls.CSV_COLUMNS)
            for rec in records:
                writer.writerow([rec.id, f"{rec.timestamp:.6f}", rec.otp])

        return target_path

    @classmethod
    def export_manifest(
        cls,
        generator: OTPGeneratorStrategy,
        records: list[OTPRecord],
        csv_path: Path,
        manifest_path: str | Path,
        entropy_report: EntropyReport | None = None,
    ) -> Path:
        """Genera y guarda el manifiesto en formato JSON para auditoría de caja blanca.

        Incluye los campos mínimos requeridos: algoritmo (`python_random_randint`),
        longitud del token, tamaño de muestra, semilla inicial utilizada, fecha de
        generación (ISO-8601 UTC y UNIX timestamp), hash SHA-256 del CSV y métricas
        preliminares de entropía.

        Args:
            generator: Instancia de la estrategia generadora empleada.
            records: Lote de registros OTP emitidos.
            csv_path: Ruta al archivo CSV previamente exportado.
            manifest_path: Ruta donde se guardará el archivo `manifest.json`.
            entropy_report: Reporte opcional de entropía para adjuntar al manifiesto.

        Returns:
            Objeto Path resuelto del manifiesto JSON creado.
        """
        target_manifest = Path(manifest_path)
        target_manifest.parent.mkdir(parents=True, exist_ok=True)

        now_utc = datetime.now(timezone.utc)
        csv_sha256 = cls.compute_sha256(csv_path) if csv_path.is_file() else None

        manifest_data: dict[str, Any] = {
            "role": "Evaluador",
            "cwe_reference": "CWE-330: Use of Insufficiently Random Values",
            "algorithm": generator.algorithm_name,
            "token_length": generator.digits,
            "sample_size": len(records),
            "initial_seed": generator.seed,
            "generation_date": now_utc.isoformat(),
            "generation_unix_timestamp": int(now_utc.timestamp()),
            "dataset_file": str(csv_path.as_posix()),
            "dataset_sha256": csv_sha256,
            "generator_details": generator.get_metadata(),
        }

        if entropy_report is not None:
            manifest_data["preliminary_entropy_metrics"] = entropy_report.to_dict()

        with target_manifest.open(mode="w", encoding="utf-8") as json_file:
            json.dump(manifest_data, json_file, indent=4, ensure_ascii=False)

        return target_manifest

