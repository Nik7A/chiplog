"""Sink implementations.

v0.1 ships the Sink protocol + an in-memory sink for tests.
LocalFileSink with WAL and manifest lands in Step 4.
S3Sink with Object Lock, PostgresSink with role separation, and MultiSink
fan-out land in v0.2.
"""
