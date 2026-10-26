# Reference assets

`ts48-test-profile/` contains GSMA TS.48 Generic eUICC Test Profile material,
including profile variants and supporting documents. The archive is also kept
at `ts48-test-profile.zip`.

The [GTP analysis module](../esim/gtp/analyze.py) reads these files relative to
the repository checkout. After an editable installation:

```bash
esim gtp analyze
```

This command inspects local files and does not access a phone. Test-profile
material is distinct from a production profile delivery package.

Keep reference inputs here and new run output in `.sessions/`. Upstream terms
apply to third-party material; this repository declares no additional license.
