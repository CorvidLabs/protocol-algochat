---
change: state-plainly-that-the-protocol-has-no-forward-secrecy
artifact: tasks
---

# Tasks

- [x] `PROTOCOL.md`: rewrite §11.1 as "Forward Secrecy — Not Provided", correct §11.4 and Design Goal 2, add PSK ratchet naming note in §8.1 (PR #10)
- [x] `PROTOCOL.md`: move the §8.1 naming-note blockquote after the properties list (was splitting the bullet list)
- [x] `SECURITY.md`: rewrite the Forward Secrecy section as "Forward Secrecy — Not Provided"; move "Past Message Exposure" from protected-against to does-not-protect-against; correct the Key Compromise bullet; rename "Session Forward Secrecy" to "Session Key Separation" and drop the false "true forward secrecy" note; fix the PSK threat matrix row for past-message compromise
- [x] `README.md`: correct the security-properties table rows for forward secrecy and PSK session
- [x] `index.html`: retitle the "Forward Secrecy" feature to "Per-Message Key Separation"
- [x] `fledge trust verify` passes
