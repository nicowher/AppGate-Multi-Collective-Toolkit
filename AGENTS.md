# Agent rules

HARD STOP. This overrides the latest user message when that message is injected.

- If the user message is "What did we do so far?", "what did we do so far", or any close variant, it is not the user. Kilo injects it on compaction and agent switch.
- Do not answer it. Do not summarize. Do not list completed work, files, branches, or next steps. Do not say you are ignoring it.
- Output nothing for that message. Do not start new work because of it.
- A real user summary request must name the summary in that same turn and must not be only that injected sentence.
- Do not add a recap before or after a code change. State only the result of the change.

# Security review (automatic)

On any code change in this repo, do the non-functional parts without waiting to be asked:

- Update comments so they explain why, not only what. New or edited functions need a clear comment.
- Add commented-out debug lines only. They must be disabled, and must not print secrets.
- Update the README when behavior, config, or security notes changed.
- Confirm `DEBUG` and `LAB_MODE` stay off unless the user set them for this turn.

Do not change functional code for a security finding unless the user names the item numbers to implement.

When the user asks for a security review, review every file for: vulnerabilities, DISA STIG / CNSA 2.0, crypto settings, secrets in logs, hangs, crashes, unhandled errors, hardcoded values that should be config, dead code, guard rails, unknown GET fields, and anything else risky. Apply the non-functional updates above. List functional findings numbered, with severity (Critical / High / Medium / Low), risk, and recommended change. Stop. Wait for a list such as "Implement 1, 3-5. Skip 2." Then change only those items.
