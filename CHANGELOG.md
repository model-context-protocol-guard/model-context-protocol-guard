# Changelog

## Unreleased - 2026-09-25

- Improved the shared benchmark defense with requester-authority checks, structural context handling, canonical payload screening, and safe scope bridging; test false positives fell from 16.0% to 1.2% while block rate rose to 100% and leaks stayed at zero.
- Added no-label-leakage, literal-guard, adversarial mutation, and Hypothesis regression tests.
- Renamed labels in result files; measured values unchanged.
- Renamed project to **Model Context Protocol Guard**; Python package and command-line interface use descriptive names; GitHub home moved to the matching organization.

## 0.1.0 - 2026-09-25

- Initial implementation of Model Context Protocol Guard with transports, policy pipeline, tests, benchmarks, and formal spec.
