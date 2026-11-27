---
name: adspower-session-audit
description: Inspect AdsPower browser profiles, capture local browser observations, and track incomplete registration stages when the user requests environment verification or workflow reuse.
---

# AdsPower session audit

Read README.md for isolation limits and registration stop conditions.

Create a new profile for each new account, as requested by this user. Preserve existing profiles and their login data. Verify the selected profile ID before acting.

Run `node audit.mjs <absolute-private-state-directory>` from this folder. Open http://127.0.0.1:8765/ inside the intended AdsPower profile, enter its ID, then run the check. The server accepts reports only through its same-origin page and writes immutable JSON records outside the repository. Reports contain browser identifiers and remain local.

Compare observations across profiles and repeat after restarting a profile. A shared marker demonstrates a storage problem. Different markers support only localStorage separation for this origin. A retained marker supports persistence for that profile. Report untested storage APIs separately.

Interpret UA reduction, unsupported APIs and unavailable high-entropy hints explicitly. A matching report cannot establish actual macOS behavior or pass/fail of a service's detection system. Record complete browser build and AdsPower patch from the UI when available. Evaluate functional requirements before changing settings.

Maintain registration stage and failure summary in a local private task record. Do not write credentials, account emails, recovery data or session tokens to git. Resume a partially completed registration in its existing profile. Ask for missing external verification only at the concrete stopping point. Never infer a CAPTCHA was solved by the agent from a later page.

Publish only source files and sanitized aggregate findings. Stop the local audit server when finished.
