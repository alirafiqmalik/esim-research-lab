---
name: analyze-session
description: Load and summarize a saved capture session — ES11/ES9+ call counts, BPP blobs, logcat events
---

# Analyze Session

```bash
esim session analyze sessions/<timestamp>/
```

For a deeper look using the Python API:

```python
from esim.analysis import Session

s = Session.load("sessions/<timestamp>/")
print(s.timeline())
for call in s.es9_calls():
    print(call.method, call.url)
    print("Request:", call.request_body)
    print("Response:", call.response_body)
```

Update `.claude/notes/rsp-observations.md` with any new protocol findings.
