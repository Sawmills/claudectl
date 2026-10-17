# Passthrough Settings Merge Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Preserve user Claude settings and claudectl renewal hooks in one private launch settings file for FLT-275.

**Architecture:** Both run commands use central_session::run. Parse and validate passthrough settings once before account acquisition; retain the stripped arguments and merged user object across restarts. Compose the user object with fresh generated hooks at initial launch and after failover. Reuse the existing credential/routing settings validator.

**Tech Stack:** Rust, serde_json, existing private atomic file writer, assert_cmd and synthetic account HTTP server.

---

### Task 1: Public launch regression

**Files:** Create `tests/central_settings_test.rs`.

1. Add one fake-Claude launch test for `run work -- --settings <A2A JSON>` that records child argv and the file it reads.
2. Run `cargo test --locked --features server --test central_settings_test -j 2` through testslot. Expect RED: current preflight refuses --settings.
3. Implement only enough shared launch handling to pass; verify exactly one settings argument, both A2A keys and all generated hooks.

### Task 2: Ordered merge and failure behavior

**Files:** Create `src/central_settings.rs`; modify `src/central.rs`, `src/central_session.rs`, `src/exec.rs`; extend the launch test.

1. Add one test at a time for mixed JSON/file inputs and --settings=value, later non-hook values winning, deep object merging and appended hook arrays.
2. Extract the existing settings-value credential/routing check without changing its rules. Apply it to each supplied object before any account acquisition.
3. Refuse missing values, unreadable files, invalid/non-object JSON and hook shapes that can replace generated hooks. Keep --bare and --setting-sources refused.
4. Keep a single immutable user overlay for renewal and failover; generate a fresh file using each session directory. Pass generated settings before any literal -- delimiter.
5. Test one-shot launches and settings persistence across supervised restart, without live provider requests.

### Task 3: Delivery

**Files:** Modify `README.md`, `Cargo.toml`, `Cargo.lock`.

1. Document both run commands, order/append behavior, isolation checks and fail-fast errors; add an A2A example. Bump package/lock version to 0.1.31.
2. Run focused launch/renewal/failover tests, fmt, and locked all-target/all-feature Clippy. Use the existing target directory, two jobs and a 30 GiB disk floor.
3. Run one autoreview and independent Standards/Spec reviews. Commit only this ticket, push one PR, request exact-head Architect and HQ reviews.
4. Merge on approvals and green CI with one installed helper submission. Tag/release v0.1.31, watch tap PR, install/verify devbox. HQ owns Mac installs and pilot relaunch acceptance.
