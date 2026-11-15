"""Interfaces base y estructuras de datos para los generadores de OTP."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OTPRecord:
    """Representa un registro individual de código OTP emitido en el servidor.

    Attributes:
        id: Índice secuencial consecutivo (ej. 0 a N-1).
        timestamp: Marca de tiempo UNIX (en segundos con precisión de microsegundos)
            del instante exacto de emisión.
        otp: Cadena numérica del código OTP con relleno de ceros a la izquierda.
    """

    id: int
    timestamp: float
    otp: str


class OTPGeneratorStrategy(ABC):
    """Interfaz abstracta (Patrón Strategy) para generadores de códigos OTP.

    Permite desacoplar el motor de simulación respecto al algoritmo PRNG/CSPRNG
    específico, facilitando la adición de nuevos generadores en el futuro.
    """

    def __init__(self, digits: int = 4, seed: int | None = None) -> None:
        """Inicializa y valida los parámetros comunes del generador.

        Args:
            digits: Longitud en dígitos decimales del código OTP (por defecto 4).
            seed: Semilla de inicialización explícita. Si es None, la estrategia
                puede derivarla del reloj UNIX del sistema.

        Raises:
            ValueError: Si la cantidad de dígitos es menor o igual a cero.
        """
        if digits <= 0:
            raise ValueError(f"La longitud del OTP debe ser mayor a 0 (recibido: {digits}).")
        self._digits: int = digits
        self._seed: int | None = seed

    @property
    def digits(self) -> int:
        """Devuelve la longitud configurada de dígitos decimales."""
        return self._digits

    @property
    def seed(self) -> int | None:
        """Devuelve la semilla efectiva utilizada para inicializar el generador."""
        return self._seed

    @property
    @abstractmethod
    def algorithm_name(self) -> str:
        """Identificador canónico del algoritmo para el manifiesto de auditoría."""

    @abstractmethod
    def generate_one(self, seq_id: int) -> OTPRecord:
        """Genera un único código OTP junto con sus metadatos síncronos.

        Args:
            seq_id: Identificador secuencial del token dentro del lote.

        Returns:
            Instancia de OTPRecord con el código formateado y su timestamp.
        """

    def generate_batch(self, count: int = 100) -> list[OTPRecord]:
        """Genera un lote secuencial de códigos OTP.

        Args:
            count: Cantidad total de códigos OTP a generar (por defecto 100).

        Returns:
            Lista de registros OTPRecord ordenados secuencialmente.

        Raises:
            ValueError: Si count es menor o igual a cero.
        """
        if count <= 0:
            raise ValueError(f"El tamaño de muestra debe ser mayor a 0 (recibido: {count}).")
        return [self.generate_one(seq_id=i) for i in range(count)]

    def get_metadata(self) -> dict[str, Any]:
        """Devuelve los metadatos técnicos de configuración del generador."""
        return {
            "algorithm": self.algorithm_name,
            "digits": self._digits,
            "seed": self._seed,
        }

