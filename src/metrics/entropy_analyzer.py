"""Analizador de Entropía de Shannon y frecuencias de distribución para códigos OTP."""

from __future__ import annotations

import csv
import math
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EntropyReport:
    """Estructura de resultados del análisis de entropía sobre un lote de OTPs.

    Attributes:
        sample_size: Cantidad total de códigos OTP evaluados (N).
        token_length: Longitud en dígitos de cada código (d).
        unique_tokens: Cantidad de códigos OTP únicos observados en la muestra.
        token_shannon_entropy_bits: Entropía de Shannon empírica sobre los tokens completos.
        max_theoretical_token_entropy_bits: Cota máxima teórica d * log2(10) (~13.2877 bits para d=4).
        max_sample_entropy_bits: Entropía máxima alcanzable dado el tamaño de muestra min(log2(N), d*log2(10)).
        digit_shannon_entropy_bits: Entropía de Shannon global sobre los dígitos individuales (0-9).
        max_theoretical_digit_entropy_bits: Cota máxima por dígito log2(10) (~3.3219 bits/dígito).
        digit_efficiency: Eficiencia entrópica normalizada por dígito [0.0, 1.0].
        positional_entropy_bits: Entropía de Shannon calculada por cada posición (columna) del código.
        digit_counts: Conteo absoluto de cada dígito '0'-'9' en toda la muestra.
        digit_frequencies: Frecuencia relativa (proporción) de cada dígito '0'-'9'.
    """

    sample_size: int
    token_length: int
    unique_tokens: int
    token_shannon_entropy_bits: float
    max_theoretical_token_entropy_bits: float
    max_sample_entropy_bits: float
    digit_shannon_entropy_bits: float
    max_theoretical_digit_entropy_bits: float
    digit_efficiency: float
    positional_entropy_bits: list[float]
    digit_counts: dict[str, int]
    digit_frequencies: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        """Convierte el reporte a un diccionario serializable en JSON."""
        return asdict(self)


class EntropyAnalyzer:
    """Calculadora de Entropía de Shannon y distribución de frecuencias para lotes OTP."""

    DIGITS_ALPHABET: tuple[str, ...] = tuple(str(d) for d in range(10))

    @staticmethod
    def calculate_shannon_entropy(counts: Counter[str], total: int) -> float:
        """Calcula la Entropía de Shannon H(X) = -sum(p(x) * log2(p(x))) en bits.

        Args:
            counts: Mapa de frecuencias observadas por símbolo.
            total: Número total de elementos observados.

        Returns:
            Valor de entropía en bits (redondeado a 6 decimales).
        """
        if total <= 0:
            return 0.0

        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p_x = count / total
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 6)

    @classmethod
    def analyze_tokens(cls, tokens: list[str]) -> EntropyReport:
        """Analiza una lista de códigos OTP y genera el reporte completo de entropía.

        Args:
            tokens: Lista de cadenas OTP (ej. ["0421", "9812", ...]).

        Returns:
            Instancia de EntropyReport con todas las métricas calculadas.

        Raises:
            ValueError: Si la lista está vacía o los tokens tienen longitudes inconsistentes.
        """
        if not tokens:
            raise ValueError("La lista de tokens OTP para analizar no puede estar vacía.")

        token_length = len(tokens[0])
        if token_length == 0:
            raise ValueError("Los tokens OTP no pueden ser cadenas vacías.")

        for idx, token in enumerate(tokens):
            if len(token) != token_length or not token.isdigit():
                raise ValueError(
                    f"Token inválido en índice {idx}: '{token}'. "
                    f"Se esperaba cadena numérica de {token_length} dígitos."
                )

        sample_size = len(tokens)
        total_digits = sample_size * token_length

        # 1. Entropía de conjunto de tokens completos
        token_counts = Counter(tokens)
        token_entropy = cls.calculate_shannon_entropy(token_counts, sample_size)
        max_theoretical_token_entropy = round(token_length * math.log2(10), 6)
        max_sample_entropy = round(
            min(math.log2(sample_size), max_theoretical_token_entropy), 6
        )

        # 2. Distribución global y entropía de dígitos (0-9)
        all_digits_str = "".join(tokens)
        raw_digit_counts = Counter(all_digits_str)
        digit_counts: dict[str, int] = {
            d: raw_digit_counts.get(d, 0) for d in cls.DIGITS_ALPHABET
        }
        digit_frequencies: dict[str, float] = {
            d: round(digit_counts[d] / total_digits, 6) for d in cls.DIGITS_ALPHABET
        }

        digit_entropy = cls.calculate_shannon_entropy(raw_digit_counts, total_digits)
        max_digit_entropy = round(math.log2(10), 6)
        digit_efficiency = (
            round(digit_entropy / max_digit_entropy, 6) if max_digit_entropy > 0 else 0.0
        )

        # 3. Entropía posicional por columna (D_1, ..., D_d)
        positional_entropies: list[float] = []
        for pos in range(token_length):
            column_digits = [t[pos] for t in tokens]
            col_counts = Counter(column_digits)
            col_entropy = cls.calculate_shannon_entropy(col_counts, sample_size)
            positional_entropies.append(col_entropy)

        return EntropyReport(
            sample_size=sample_size,
            token_length=token_length,
            unique_tokens=len(token_counts),
            token_shannon_entropy_bits=token_entropy,
            max_theoretical_token_entropy_bits=max_theoretical_token_entropy,
            max_sample_entropy_bits=max_sample_entropy,
            digit_shannon_entropy_bits=digit_entropy,
            max_theoretical_digit_entropy_bits=max_digit_entropy,
            digit_efficiency=digit_efficiency,
            positional_entropy_bits=positional_entropies,
            digit_counts=digit_counts,
            digit_frequencies=digit_frequencies,
        )

    @classmethod
    def analyze_csv(cls, csv_path: str | Path) -> EntropyReport:
        """Lee un archivo CSV de dataset OTP y calcula sus métricas de entropía.

        Args:
            csv_path: Ruta al archivo CSV que contiene la columna `otp`.

        Returns:
            Instancia de EntropyReport con las métricas del dataset.

        Raises:
            FileNotFoundError: Si el archivo CSV no existe.
            KeyError: Si el CSV no contiene la columna requerida `otp`.
        """
        path = Path(csv_path)
        if not path.is_file():
            raise FileNotFoundError(f"No se encontró el archivo de dataset: {path}")

        tokens: list[str] = []
        with path.open(mode="r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None or "otp" not in reader.fieldnames:
                raise KeyError(
                    f"El archivo CSV '{path}' no contiene la columna obligatoria 'otp'."
                )
            for row in reader:
                tokens.append(row["otp"].strip())

        return cls.analyze_tokens(tokens)

    @staticmethod
    def format_console_report(report: EntropyReport) -> str:
        """Formatea el reporte de entropía en una tabla legible para consola."""
        lines: list[str] = [
            "=" * 68,
            " REPORTE DE EVALUACION DE ENTROPIA Y DISTRIBUCION DE DIGITOS (OTP)",
            "=" * 68,
            f" Tamano de muestra (N)              : {report.sample_size} tokens",
            f" Longitud del token (d)             : {report.token_length} digitos",
            f" Tokens unicos observados           : {report.unique_tokens} / {report.sample_size}",
            "-" * 68,
            " METRICAS DE ENTROPIA DE SHANNON",
            "-" * 68,
            f" Entropia del conjunto de OTPs      : {report.token_shannon_entropy_bits:.6f} bits",
            f" Maximo alcanzable en muestra (log2N): {report.max_sample_entropy_bits:.6f} bits",
            f" Maximo teorico del espacio (10^d)  : {report.max_theoretical_token_entropy_bits:.6f} bits",
            f" Entropia global por digito (0-9)   : {report.digit_shannon_entropy_bits:.6f} bits/digito",
            f" Maximo teorico por digito (log2 10): {report.max_theoretical_digit_entropy_bits:.6f} bits/digito",
            f" Eficiencia entropica de digitos    : {report.digit_efficiency * 100:.2f} %",
            "-" * 68,
            " ENTROPIA POSICIONAL POR COLUMNA",
            "-" * 68,
        ]

        for idx, pos_h in enumerate(report.positional_entropy_bits, start=1):
            lines.append(f"   Posicion D_{idx:<2}                    : {pos_h:.6f} bits")

        lines.extend(
            [
                "-" * 68,
                " DISTRIBUCION DE FRECUENCIAS DE DIGITOS DECIMALES (Espacio = 10%)",
                "-" * 68,
                " Digito | Frecuencia Abs. | Frecuencia Rel. | Barra visual",
                "-" * 68,
            ]
        )

        for digit in EntropyAnalyzer.DIGITS_ALPHABET:
            count = report.digit_counts[digit]
            freq_pct = report.digit_frequencies[digit] * 100.0
            bar = "#" * int(round(freq_pct))
            lines.append(f"   {digit}    |     {count:>6d}      |     {freq_pct:>6.2f} %    | {bar}")

        lines.append("=" * 68)
        return "\n".join(lines)

