<!-- For a LEADERBOARD submission, confirm each box. For spec/code changes, describe the change. -->

## Leaderboard submission (delete if N/A)

- [ ] Manifest added under `leaderboard/manifests/` and one entry added to `leaderboard/entries.json`
- [ ] Target was scored on **loopback only** (no live third-party/production endpoint)
- [ ] Self-authored targets are disclosed as such in the entry `notes`
- [ ] Model snapshot, temperature, and trial count `N` are pinned in the manifest
- [ ] `python leaderboard/build_site.py` passes locally (the verifier confirms the manifest)

## Spec / code change (delete if N/A)

- [ ] Does not alter a frozen field (task id, oracle class, mode, weight) without a version bump, see SPEC §9
- [ ] `python -m pytest tests/ -q` passes
