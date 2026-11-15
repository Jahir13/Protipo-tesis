"""Fábrica (Patrón Factory) para instanciar estrategias de generación de OTP."""

from __future__ import annotations

from typing import Type

from src.generators.base import OTPGeneratorStrategy
from src.generators.python_random_generator import PythonRandomRandintGenerator


class OTPGeneratorFactory:
    """Fábrica centralizada de generadores de códigos OTP.

    Permite registrar y crear instancias de estrategias PRNG/CSPRNG a partir
    de su identificador de algoritmo sin acoplar el código cliente.
    """

    _registry: dict[str, Type[OTPGeneratorStrategy]] = {
        PythonRandomRandintGenerator.ALGORITHM_ID: PythonRandomRandintGenerator,
    }

    @classmethod
    def register(cls, algorithm_id: str, strategy_cls: Type[OTPGeneratorStrategy]) -> None:
        """Registra una nueva estrategia de generación OTP en la fábrica.

        Args:
            algorithm_id: Nombre identificador único del algoritmo.
            strategy_cls: Clase que hereda de OTPGeneratorStrategy.

        Raises:
            TypeError: Si strategy_cls no es subclase de OTPGeneratorStrategy.
        """
        if not issubclass(strategy_cls, OTPGeneratorStrategy):
            raise TypeError(
                f"{strategy_cls.__name__} debe heredar de OTPGeneratorStrategy."
            )
        cls._registry[algorithm_id] = strategy_cls

    @classmethod
    def create(
        cls,
        algorithm_id: str = PythonRandomRandintGenerator.ALGORITHM_ID,
        digits: int = 4,
        seed: int | None = None,
    ) -> OTPGeneratorStrategy:
        """Crea e inicializa una instancia del generador solicitado.

        Args:
            algorithm_id: Identificador del algoritmo (por defecto 'python_random_randint').
            digits: Longitud del código OTP en dígitos decimales (por defecto 4).
            seed: Semilla inicial (None para derivar de timestamp UNIX).

        Returns:
            Instancia configurada de OTPGeneratorStrategy.

        Raises:
            ValueError: Si el algoritmo solicitado no está registrado.
        """
        strategy_cls = cls._registry.get(algorithm_id)
        if strategy_cls is None:
            available = ", ".join(sorted(cls._registry.keys()))
            raise ValueError(
                f"Algoritmo '{algorithm_id}' no registrado. Disponibles: [{available}]."
            )
        return strategy_cls(digits=digits, seed=seed)

    @classmethod
    def available_algorithms(cls) -> list[str]:
        """Devuelve la lista de identificadores de algoritmos disponibles."""
        return sorted(cls._registry.keys())

