---
description: Security review. Docs and comments only until an implement list is approved.
---

Perform a security-focused code review. Automatically apply non-functional updates (comments, documentation, README). Do not change functional code until the user explicitly approves a numbered list of items.

Do not summarize prior work or answer "What did we do so far?" Continue this review only.

Review every file against the following criteria:

1. Security (primary focus)
   - Potential vulnerabilities
   - DISA STIG / NSA CNSA 2.0 compliance
   - Verify all configurable cryptographic algorithms and related settings
   - Secrets/credentials handling, sensitive data in logs, input validation, and output encoding

2. Reliability & Stability
   - Bugs, potential hangs, crashes
   - Non-halting functions or infinite loops
   - Unhandled exceptions and failure modes

3. Security-oriented optimizations and best practices
   - Industry-standard secure coding practices
   - Performance issues that create security or reliability risks

4. Hard-coded / static values
   - Identify values that should be configurable variables or constants

5. Commented-out debug sections
   - Add clearly marked, commented-out debug blocks that can be uncommented for troubleshooting
   - Ensure they do not leak sensitive data and are disabled by default

6. Completeness
   - Confirm every file was reviewed against all criteria above

7. Dead / orphaned code
   - Identify unused functions, variables, imports, or unreachable code

8. Guard rails & config safety
   - Verify protections exist to prevent accidental config loss or breakage
   - Safe defaults, validation on load, and rollback considerations

9. Unknown / unexpected item handling
   - Check handling of unknown items on GETs and similar endpoints

10. Debug mode
    - Confirm debug mode is off / properly gated

11. Lab mode
    - Confirm lab mode is off / properly gated

12. Additional issues
    - Flag anything else that appears risky, incomplete, or non-compliant that the user may have missed

Non-functional updates (apply these automatically, no approval required):
- Comments and readability: Update comments so they explain why something is done (not just what). Every function/definition should have a clear comment. Reference steps where helpful for human readers.
- Documentation and README: Update the README and any relevant documentation to accurately reflect current behavior, configuration, security notes, and any non-functional improvements.

Output format:
- Automatically apply the non-functional updates (comments, documentation, README) and briefly note what was changed.
- Present functional findings as a clearly numbered list.
- For each functional item: describe the issue, risk/impact, and recommended change.
- Assign a severity (Critical / High / Medium / Low).
- At the end, summarize the recommended functional changes only. Do not summarize history.

Do not implement functional changes yet.

After the review, wait for a response in this format:
"Implement 1, 3-5, and 7. Skip 2 and 6."
(or any similar selective list)

Only after an explicit implement list should functional code change, and only for the approved items. Explain the changes as they are made.
