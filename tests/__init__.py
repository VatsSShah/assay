"""Assay test suite.

Written against the standard library's ``unittest`` rather than pytest, for three reasons:

1. The project's headline claim is that everything here runs on the standard library alone.
   A test suite that needed a third-party runner contradicted that claim.
2. ``python -m unittest discover`` used to report "Ran 0 tests ... OK" -- a green result
   that meant nothing was executed. That is a worse failure mode than a red one.
3. pytest collects ``unittest.TestCase`` subclasses natively, so ``python -m pytest tests/``
   still works for anyone who prefers it.
"""
