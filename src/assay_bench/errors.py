"""Typed errors and stable process exit codes.

``assert`` is never used for input validation anywhere in Assay: ``python -O``
removes assertions, which would silently turn a rejecting verifier into an
accepting one. Every rejection below is an explicit exception.
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_USAGE = 2
EXIT_MALFORMED = 3


class AssayError(Exception):
    """Base class. ``exit_code`` is the process status a CLI should return."""

    exit_code = EXIT_VERIFICATION_FAILED


class UsageError(AssayError):
    exit_code = EXIT_USAGE


class MalformedInput(AssayError):
    """Input could not be parsed or violates the structural schema."""

    exit_code = EXIT_MALFORMED


class ValidationError(AssayError):
    """Input parsed but failed a semantic rule (an invariant the standard requires)."""


class VerificationFailed(AssayError):
    """A manifest did not reach a verification level that was required."""


class UnsupportedVersion(AssayError):
    """The artifact declares a benchmark/manifest version this build cannot handle."""


class AdapterError(AssayError):
    """A target adapter failed, timed out, or violated its declared capabilities."""


class PrecommitmentError(AssayError):
    """A precommitment record is missing, mismatched, reused, or not provably earlier."""
