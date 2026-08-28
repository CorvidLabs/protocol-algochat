---
change: pin-trust-1-2-0-rc-1-so-ci-uses-specsync-6-0-0-rc-9
artifact: context
---

# Context

Trust 1.0.0 pins SpecSync 5.0.1. Falcon 1.2 landed with SpecSync 6 RC change
workspaces; 5.0.1 rejected slug IDs and treated draft coverage as an error.

Trust [v1.2.0-rc.1](https://github.com/CorvidLabs/trust/releases/tag/v1.2.0-rc.1)
defaults SpecSync to 6.0.0-rc.9 (`783a6d0ce2089c0f5c109dc795ac156518325727`)
and leaves lifecycle-enforce off. Pin the composed action to
`e964e042f7f2756333d4c46e685a4a6dc09077de`. Do not move the protected `v1`
channel. This is a prerelease.

No protocol text changes.
