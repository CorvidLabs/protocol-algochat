<!-- CorvidLabs trust toolchain: BEGIN (managed, do not edit inside) -->
## CorvidLabs trust toolchain

This repository uses one trust gate. Every session must use it and must not bypass or weaken it.

- Run `fledge trust verify` before calling a change complete.
- Keep module specs synchronized with implementation changes.
- Treat an Augur block verdict as a hard stop that must be surfaced and de-risked.
- Record and verify provenance with Attest after the repository's verification lane passes.
- Keep generated trust configuration and this managed block in place.

<!-- CorvidLabs trust toolchain: END -->


## Human intent

This repository should use [hi (Human Intent)](https://corvidlabs.xyz/hi): plain
sentences saying what people want, each with a permanent id, kept in `hi/`.
Tickets and specs are generated from them.

If there is no `hi/` here yet, start one from real work rather than from the code:

1. When I ask for a feature, draft its criteria first — one plain sentence each,
   about what somebody **wants**, not what the code does. Private test: you should
   be able to put *As a ___,* in front of it. Leave those words out of the file.
2. Show them to me and stop. Capture nothing I have not agreed to.
3. Capture what I confirm, one per command: `hi SEND-1 "the sentence, in my words"`.
   You pick the id. Letters are cases and numbers are steps (`SEND-1.a.1`), and an
   id is permanent and never reused, so choose like you will say it out loud.
4. Then build. `hi check` fails only on a structurally broken file, never on
   unfinished intent.

Do this before every feature, not only the first one. Do **not** bulk-generate
criteria from the code or from existing tickets: a hundred plausible sentences
nobody said is worse than five real ones, and an id spent on a wrong sentence is
spent forever.

Install: `brew install corvidlabs/tap/hi`, or `cargo install human-intent`.
