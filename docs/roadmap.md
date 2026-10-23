# Implementation milestones

| Milestone | Deliverable | Exit evidence |
|---|---|---|
| M0 — design and harness | Public design, catalog, pinned contract sources, offline SDK characterization, CI | Required CI checks pass; known differences remain visible |
| M1 — read-only | v1 boundary compatibility, Entity persistence, capability probes, PEM/binding discovery | Relevant catalog cases implemented; optional private read-only acceptance |
| M2 — staging | Durable operations/locks, device CSR, ACME external CSR, approved chain import | Offline fault cases pass; private stage-only acceptance; active TLS unchanged |
| M3 — activation | Switch intent, independent TLS, guarded persistence, recovery | Crash/timeout tests pass; controlled activation and rollback accepted |
| M4 — automation and preview release | Scheduling, order recovery, Core sync, release provenance | Scheduler and artifact gates pass; no unimplemented required acceptance cases |

The design and harness commits precede production implementation. There is
no executable connector in M0. The first implementation change should be a
small PR that starts with failing M1 tests, then implements only read-only
behavior. Add each later phase's failure tests before its device mutations.

Open environment questions become private lab acceptance evidence when the
relevant stage is reached. They do not block offline development. A successful
mock response does not close a device capability question.
