# Reporting a security problem

HSLSA's verifier decides whether a buyer accepts parts, so a bug that makes it accept a record it should refuse is a security problem: a forged or unsigned record that passes, a revoked or unenrolled key that still counts, a withheld field that leaks, or a lot or unit that the receipt check matches wrongly.

Report it privately, not in an issue or a pull request:

- If you can open this repository on GitHub, use **Security > Report a vulnerability**.
- If you received the pilot kit as a tarball, write to the contact named in your pilot agreement ([pilot/agreement.md](pilot/agreement.md)).

Include the `KIT.txt` of your kit or the commit you ran, the command, and the records or a way to make them. Keep real supplier data out of the report unless the agreement allows it; a reproduction on the sample exports in `e2e/` is enough.

A fix lands as a new spec revision or tool change with a changelog entry, and pilot parties get a new kit.

## What is not a vulnerability

- A signed record whose claim is false. A signature proves who made a claim, not that it is true ([threat model](spec/hslsa-v0.1.md#what-a-signed-record-proves)).
- Attacks the threat model lists as out of reach for the level claimed.
- The test keys and S.A.F.E. fixtures under `tools/hslsa/testdata/` and the keys the examples generate. They are throwaway keys.
