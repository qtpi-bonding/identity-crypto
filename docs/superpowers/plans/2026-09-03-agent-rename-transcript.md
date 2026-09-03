# Agent-rename transcript Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one new canonical, domain-separated transcript function,
`rename_transcript`, so grorg can let an agent rename itself by signing a
challenge response with its own root key — reusing the existing
self-proof/challenge machinery rather than an unauthenticated endpoint.

**Architecture:** One pure function in `src/transcripts.rs`, following the
exact byte-layout convention every other transcript in this file already
uses (domain tag, then length-prefixed variable fields, then fixed-width
scalars). No new proto types, no new dependencies.

**Tech Stack:** Rust, no new crates.

**Spec:** [concordat/2026-09-03-single-path-agent-registration-design.md](../../../../../systematic-action/concordium/concordat/2026-09-03-single-path-agent-registration-design.md)
(§"Renaming reuses the registration proof, not a new unauthenticated
endpoint")

## Global Constraints

- Domain tag format: NUL-terminated ASCII string matching the pattern of
  every existing transcript (`b"grorg.key-challenge.v1\0"`,
  `b"grorg.key-delegation.v1\0"`, etc.) — this one is
  `b"grorg.agent-rename.v1\0"`.
- Variable-length byte/string fields are length-prefixed with a 4-byte
  big-endian `u32` (`with_len_prefixed`, already defined in this file —
  reuse it, do not reimplement).
- No consumer (grorg, gait, multimatrix) is touched by this plan — this
  crate stays a pure, dependency-free primitive. Grorg's own plan
  (separate, `concordium/grorg`) is the one that calls this function.

---

### Task 1: Add `rename_transcript`

**Files:**
- Modify: `src/transcripts.rs`

**Interfaces:**
- Produces: `pub fn rename_transcript(agent_id: &str, new_name: &str) -> Vec<u8>` —
  grorg's `rename_agent` ops-layer function (a different repo's plan)
  will call this exactly the way `delegation_transcript`/
  `revocation_transcript` are called today: build the transcript, then
  `verify_ed25519(&current_root.public_key, &transcript, &signature)`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in `src/transcripts.rs`
(append after `rotation_transcript_binds_agent_id_and_new_key`, matching
the style of every other transcript's test pair):

```rust
    #[test]
    fn rename_transcript_has_stable_domain_and_layout() {
        let t = rename_transcript("agent-a", "new-name");
        assert!(t.starts_with(b"grorg.agent-rename.v1\0"));
        // domain(22) + len-prefix(4) + "agent-a"(7) + len-prefix(4) + "new-name"(8)
        assert_eq!(t.len(), 22 + 4 + 7 + 4 + 8);
    }

    #[test]
    fn rename_transcript_binds_agent_id() {
        let a = rename_transcript("agent-a", "same-name");
        let b = rename_transcript("agent-b", "same-name");
        assert_ne!(a, b, "different agent_id must produce a different transcript");
    }

    #[test]
    fn rename_transcript_binds_new_name() {
        let a = rename_transcript("agent-a", "old-name");
        let b = rename_transcript("agent-a", "new-name");
        assert_ne!(a, b, "different new_name must produce a different transcript");
    }

    #[test]
    fn rename_transcript_domain_never_collides_with_delegation_transcript() {
        // Same agent_id happens to be embedded in both; different domains
        // and different trailing shapes must still never collide.
        let key = [3u8; 32];
        let delegation = delegation_transcript("agent-x", &key, 1);
        let rename = rename_transcript("agent-x", "agent-x");
        assert_ne!(delegation, rename);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib rename_transcript`
Expected: FAIL with "cannot find function `rename_transcript` in this scope"

- [ ] **Step 3: Implement `rename_transcript`**

Add to `src/transcripts.rs`, directly after `delegation_transcript` (keeps
the file's existing ordering: self-proof, delegation, revocation,
rotation, then this one logically belongs beside delegation since both
are "an existing root authorizes a change to this agent's record"):

```rust
/// `RenameAgent`'s authorization signature: the agent's current root key
/// vouching for a new human-facing name. No self-proof half needed here
/// (unlike `AddAgentKey`) -- there's no new key being introduced, only an
/// existing root re-asserting its own agent's label.
pub fn rename_transcript(agent_id: &str, new_name: &str) -> Vec<u8> {
    let mut buf = b"grorg.agent-rename.v1\0".to_vec();
    with_len_prefixed(&mut buf, agent_id.as_bytes());
    with_len_prefixed(&mut buf, new_name.as_bytes());
    buf
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib rename_transcript`
Expected: PASS (all 4 new tests)

- [ ] **Step 5: Run the full crate test suite**

Run: `cargo test --lib`
Expected: PASS (no existing test touched)

- [ ] **Step 6: Commit**

```bash
git add src/transcripts.rs
git commit -m "feat: add rename_transcript for agent self-rename authorization"
```

- [ ] **Step 7: Push and record the new commit hash**

```bash
git push origin main
git rev-parse HEAD
```

Record the resulting short hash — grorg's plan bumps its `Cargo.toml`
`identity-crypto` git `rev` to this commit as its first task.
