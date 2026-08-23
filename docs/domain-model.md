# Domain model

`Person` is the human record and carries lifecycle state. `IdentityAccount` is one account observed through one connector. `IdentityLink` states why the account belongs to the person; `CorrelationCandidate` preserves uncertain matches for review. This separation prevents account state from silently changing person lifecycle state.

`Entitlement` and `AccessGrant` represent groups, roles and provider membership. `IdentityFinding` records explainable drift such as orphan accounts, terminated people with active accounts and duplicate active accounts. Findings are observations requiring context, not declarations of malicious behavior.

`LifecycleCase` is the approval boundary for a single person. It owns planned `LifecycleAction` records, immutable action attempts, events, `VerificationSnapshot` conclusions and `IdentityEvidence`. `AccessReviewCampaign` records periodic reviewer decisions; `REVOKE` proposes controlled lifecycle work and does not call a provider directly.
