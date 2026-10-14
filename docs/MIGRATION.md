# Preserving the existing implementation progress

## Current situation

The original `k1moradi/xrdp-console` GitHub repository was deleted before
the full source tree was migrated. The current `RDP-server` repository has
125 selectively imported C++23 source/header files and a passing independent
C++23 protocol library, **but it is not the whole original project**.

The goal is to preserve code and engineering progress, **not the old Git
commit history**. In particular we must not lose unfinished clipboard work,
graphics tests, project sources or alternative fixes which were on
development branches.

## Source snapshot import

The [current-progress importer](../scripts/import-current-progress.py)
reads the original development PC's existing `~/xrdp-console` Git checkout.
It does **not** need the deleted GitHub remote.

It preserves:

- Every tracked file from the most advanced available original `main`
  snapshot. Files absent from the new repository enter at their original
  paths. Existing new C++23 files take priority; old versions of overlapping
  paths remain under `migration/source-main-overlaps/`.
- The newest locally available `dev/clipboard` or
  `experiment/png-prefetch-native-review-20261013` implementation's
  **actual changed files**, under `migration/clipboard-delta/`.
- Code from every available independent *maximal* development tip,
  under `migration/other-tip-deltas/`; already-integrated ancestor refs
  are not duplicated.
- Tracked but uncommitted local changes under
  `migration/local-working-changes/`.
- A machine-readable file inventory under
  `migration/PROGRESS_INVENTORY.json`. Deleted or absent files are listed
  explicitly rather than silently forgotten.

Old patched-xrdp C/vendor files, packaging and GitHub workflows are kept
under `migration/source-main/`, **not** activated or linked into the
independent C++23 default build. Importing code is not equivalent to
completing its C++23 port. Untracked/ignored local files and remote branch
tips not present in the local Git checkout cannot be recovered automatically;
inspect the inventory for these limitations.

## Run from the development PC

If `~/RDP-server` does not exist:

```bash
cd ~
git clone https://github.com/k1moradi/RDP-server.git
cd RDP-server
python3 scripts/import-current-progress.py /home/keivan/xrdp-console
```

If the new repository is already checked out:

```bash
cd ~/RDP-server
git pull --ff-only
python3 scripts/import-current-progress.py /home/keivan/xrdp-console
```

The deprecated `bash scripts/import-full-project.sh` command now invokes
**the same source-only importer**. It does not import old Git history.

The importer updates only the existing `main`, commits the source
snapshots, and pushes normally. It does not make a branch, force-push,
create a rollback backup, change or activate an RDP service, or disturb
the old development checkout. It refuses to proceed if it cannot find
the old clipboard experiment because losing that work is unacceptable.

### Acceptance after importing

- Verify the GitHub repository now includes `src/module/`, `tests/`,
  `tools/`, the retained source material and
  `migration/PROGRESS_INVENTORY.json`.
- Check the clipboard and independent-tip inventories against the source
  development PC. Continue actively reconciling needed source into the
  actual C++23 targets and tests; archived deltas are **preserved**, not
  yet compiled or merged into the functional protocol path.
- Run the standalone Linux/macOS/Windows C++23 CI and resolve any
  build/test regressions before advertising a working RDP server.

If `~/xrdp-console` was deleted locally as well, the missing files are
unavailable through the GitHub connector. Restore the old GitHub repository
through GitHub's deleted-repository recovery settings if it is still eligible,
then recover its source to a local checkout.

**Do not call the migration complete until the source snapshot import has
actually run and the resulting files are verified on `RDP-server/main`.**
