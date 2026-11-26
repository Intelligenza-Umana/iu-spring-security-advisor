# Contributing

Contributions are welcome, including from developers who are new to security tooling. Open an issue describing the problem, evidence and expected behavior before substantial changes. Do not include exploitable vulnerability details or secrets in public issues; follow the foundation's [security policy](https://github.com/fabiozagaria/intelligenza-umana/blob/main/SECURITY.md) for private reporting.

For scanner rules, explain the threat and cite an authoritative source. Add positive and negative fixture cases, account for false positives and false negatives, and document limitations. The score is an aid to review, not a security certification. Keep the scanner dependency-free and preserve documented output compatibility.

For skills and documentation, explain the intended behavior and update the relevant tests and references. AI assistance is welcome when contributors understand and review their changes.

Before opening a pull request, run:

```bash
python3 -m unittest discover -s tests -v
```

Include the actual results, limitations and any checks you could not run. Maintainers review changes according to risk; high-risk changes require independent review before a stable release.
