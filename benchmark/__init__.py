"""
Security Benchmark Package for Evidence-Backed Release Assurance.
"""

from .tamper_vectors import (
    TAMPER_VECTOR_TAXONOMY,
    generate_tampered_evidence_suite
)

__all__ = [
    "TAMPER_VECTOR_TAXONOMY",
    "generate_tampered_evidence_suite"
]
