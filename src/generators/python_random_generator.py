"""Implementación del generador OTP débil basado en random.randint (MT19937).

Simula la vulnerabilidad CWE-330 (Use of Insufficiently Random Values) al emplear
el PRNG estadístico estándar de Python (Mersenne Twister) inicializado con una
semilla fija o derivada del tiempo UNIX.
"""

from __future__ import annotations

import random
import time
from typing import Any

from src.generators.base import OTPGeneratorStrategy, OTPRecord


class PythonRandomRandintGenerator(OTPGeneratorStrategy):
    """Estrategia de generación OTP que utiliza exclusivamente `random.randint()`.

    Utiliza el PRNG Mersenne Twister (MT19937) de la librería estándar de Python.
    Si no se proporciona una semilla explícita, toma el timestamp UNIX actual
    en segundos enteros (`int(time.time())`), dejando la semilla registrada
    para validación de caja blanca por parte del módulo Predictor.
    """

    ALGORITHM_ID: str = "python_random_randint"

    def __init__(
        self,
        digits: int = 4,
        seed: int | None = None,
        seed_mode: str = "unix_time",
    ) -> None:
        """Inicializa el generador Mersenne Twister y fija su semilla.

        Args:
            digits: Cantidad de dígitos decimales por token (por defecto 4).
            seed: Semilla entera explícita. Si es None, se usa el reloj UNIX.
            seed_mode: Modo descriptivo de la semilla ('fixed' o 'unix_time').

        Raises:
            ValueError: Si digits <= 0 o si seed_mode no es válido.
        """
        if seed is None:
            resolved_seed = int(time.time())
            self._seed_mode = "unix_time"
        else:
            resolved_seed = int(seed)
            self._seed_mode = "fixed"

        super().__init__(digits=digits, seed=resolved_seed)
        self._upper_bound: int = (10**self._digits) - 1

        # Se inicializa el generador estándar random de Python con la semilla resuelta
        random.seed(self._seed)

    @property
    def algorithm_name(self) -> str:
        """Devuelve el identificador del algoritmo para el manifiesto."""
        return self.ALGORITHM_ID

    @property
    def seed_mode(self) -> str:
        """Devuelve el modo en que se obtuvo la semilla ('fixed' o 'unix_time')."""
        return self._seed_mode

    def generate_one(self, seq_id: int) -> OTPRecord:
        """Genera un código OTP usando exclusivamente `random.randint(0, 10^d - 1)`.

        Aplica relleno de ceros a la izquierda (`zfill`) para garantizar que
        números menores a 10^(d-1) conserven la longitud nominal de `d` dígitos
        (ej. 421 -> "0421").

        Args:
            seq_id: Índice secuencial del token (0 a N-1).

        Returns:
            Registro OTPRecord con id, timestamp UNIX y cadena OTP de d dígitos.
        """
        emission_ts: float = round(time.time(), 6)
        raw_value: int = random.randint(0, self._upper_bound)
        otp_str: str = f"{raw_value:0{self._digits}d}"
        return OTPRecord(
            id=seq_id,
            timestamp=emission_ts,
            otp=otp_str,
        )

    def get_metadata(self) -> dict[str, Any]:
        """Devuelve los metadatos extendidos del generador para el manifiesto."""
        base_meta = super().get_metadata()
        base_meta.update(
            {
                "prng_family": "Mersenne Twister (MT19937)",
                "cwe_id": "CWE-330",
                "seed_mode": self._seed_mode,
                "range_min": 0,
                "range_max": self._upper_bound,
                "zero_padded": True,
            }
        )
        return base_meta
