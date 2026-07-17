# External audit records

TamVi Agent Gate returns versioned decision records but deliberately does not own a database, queue, or ledger. Persistence is the caller's responsibility because retention, access control, durability, and compliance requirements belong to the runtime.

A minimal JSON Lines sink can serialize the record returned by the gate:

```python
import json
from datetime import datetime, timezone


def append_audit_record(result, stream, *, run_id: str) -> None:
    record = result.to_dict()
    record["recorded_at"] = datetime.now(timezone.utc).isoformat()
    record["run_id"] = run_id
    stream.write(json.dumps(record, sort_keys=True) + "\n")
    stream.flush()
```

Production callers should:

- use an append-only store or an authenticated event sink;
- add caller-owned run, task, policy, and deployment identifiers;
- restrict access and define retention before storing candidate content;
- treat the built-in redaction scan as pattern-limited, not as proof that a record is secret-free;
- decide whether sink failure must block release in their own threat model;
- never let log persistence or observability success override the gate's release status.

The record is evidence of what the gate decided from the supplied inputs. It is not proof that the worker obeyed its declared capabilities, that an artifact is authentic, or that the caller/MainBrain was uncompromised.
