"""CloudWatch anomaly and pattern analysis.

This package contains pure, deterministic functions and small stateless
classes that operate on already-fetched log events / metric datapoints. It
has no AWS dependency of its own, which makes it straightforward to unit
test with synthetic historical datasets. AWS I/O (fetching events, calling
native CloudWatch Logs Insights `pattern`/anomaly-detector APIs) lives in
`app.services.pattern_analysis` and the adapters under `app.adapters.aws`.
"""
