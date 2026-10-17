# Status Plan and Pace Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Show known subscription types for server and local accounts, and weekly consumption pace in status.

**Architecture:** The shared status path consumes subscription metadata beside usage. Server polls read the existing profile endpoint, map Claude organization types with the same mapping as Claude Code, and store only the plan in the existing sealed usage projection. The client reads that additive field and uses saved credential metadata for local accounts. No account schema migration is needed.

**Tech Stack:** Rust, serde, existing reqwest clients, cached status CLI fixtures, existing server test fixtures.

## Diagnosis

`claudectl status --cached` on 0.1.31 shows Plan `-` for all six server accounts. Ranked hypotheses: server omits metadata; client drops metadata; only local credentials supply it. Source confirms all three: server usage has no plan, server_rows leaves plan empty, and display_plan labels every local account `local`. Claude Code 2.1.302 maps organization_type claude_max/pro/team/enterprise to max/pro/team/enterprise. codexctl status_pace computes used percent minus elapsed weekly percent.

## Task 1: Plan through the public status seam

Files: tests/status_plan_pace_test.rs, src/api.rs, src/commands/status.rs.

1. Seed a private server status cache with subscription_type=max; assert status --cached displays Max and status --cached --json reports plan=max. Run to RED on the original command.
2. Add optional subscription_type to UsageResponse, propagate it in server_rows, and display known plans for both local and server accounts. Local unknown remains `-`.
3. Add a Linux saved-local-profile CLI case using subscriptionType=team. Run to RED before the display fix, then GREEN.

## Task 2: Server profile metadata

Files: src/server/engine.rs, src/server/engine/usage.rs, src/server/engine/tests.rs, src/api.rs.

1. Extend the existing fake provider profile with organization_type=claude_max; exercise public engine usage then cached usage after restart and assert data.subscription_type=max. Observe RED.
2. Reuse the bounded profile lookup; verify identity matches the selected grant, map only known types, and add the plan to cached usage data on successful polls. Unknown/unavailable metadata stays null, with a bounded diagnostic on lookup failure. Cached reads make no new provider call.
3. Test non-Max types, unknown metadata, profile failure/mismatched identity, persistence and caller scoping through existing fixtures. Expose only the plan, no raw profile.

## Task 3: Weekly Pace

Files: src/commands/status.rs, tests/status_plan_pace_test.rs.

1. Public status fixtures: weekly 75% with half a week remaining is +25 ahead; 25% at half is -25 behind. Observe RED.
2. Reuse codexctl formula and wording: usage minus elapsed window, rounded signed percentage points; fresh weekly data only, valid reset within seven days, finite 0..100 percent. Missing cells show `-`; hide Pace if every account is unknown. Do not use model-specific windows.
3. Add pace_points to status JSON without removing existing fields. Test stale/error/missing/invalid windows and local/server parity. Update README with Plan, Pace and unknown behavior.

## Task 4: Verify and deliver

1. Bump Cargo.toml/Cargo.lock to 0.1.32. Run focused tests through testslot with two Cargo jobs; use low-debug owned target artifacts due shared disk pressure. Run fmt, strict all-target/all-feature Clippy, status and server suites. Hosted CI runs the complete suites.
2. One autoreview, independent Standards and Spec checks, one source PR with own lane label. Exact-head Architect and one HQ review, green checks and zero threads before one installed op-merge submission.
3. Since the server changes, select the landed source image from its CI artifact and make one staging pin. Architect/HQ + green, merge once, hand off rollout watch.
4. Tag and publish v0.1.32, watch tap landing, build and atomically install the matching aarch64 devbox binary. HQ installs both Macs and verifies live Plan/Pace. Record evidence and close only on HQ acceptance.
