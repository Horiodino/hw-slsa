# For a chip vendor receiving this kit

You make a chip with a root of trust (Caliptra or a Caliptra-class part), and you received this kit before any buyer of yours is involved. This page says what your part is, who checks your records, and where to start.

## Three parties, and who decides what

| Party | In this pilot | Decides |
| --- | --- | --- |
| **You, the chip vendor** | Sign your design, firmware and identity records with your own keys, and the HBOM for each shipped lot | Which records you produce, how your keys are held, and which fields you need withheld ([agreement.md](agreement.md)) |
| **Your OSAT** | Signs sort, assembly, test and provisioning records from the exports its MES, testers and programming station already write | The same, for its own records and keys |
| **The buyer** | Checks every lot's records before accepting the parts, and the at-boot check in its fleet | Which of your keys it trusts, which levels it requires, and whether a lot passes |

The buyer runs its own trust root: it enrolls each public key you send it, after checking it with you, and can revoke any of them. Nothing you ship in a bundle decides which keys the buyer trusts; the check uses the buyer's trust roots and policy, not ones that arrive with your records ([spec](../spec/hslsa-v0.1.md#buyer-run-trust-roots)). That is the point of the pilot: the buyer, not the supplier, decides whether the records are good enough.

## Who plays the buyer

Until one of your customers joins, the owner of this kit plays the buyer: it enrolls your keys, runs the receipt and at-boot checks on the lots you send, and shares each lot's measurement with you. When a customer of yours takes over, it does the same with its own root key, and you send it the same public keys; nothing you sign changes.

## Where to start

1. **Check the kit** as [README.md](README.md#checking-the-kit-you-received) describes, before running anything from it.
2. **Rehearse on sample data.** `e2e/pilot/run.sh chip` plays a whole pilot lot on one machine, with made-up companies, and shows every command each party runs and every check the buyer makes.
3. **Make your keys,** one per role, and send the public halves to whoever plays the buyer, with a fingerprint check over a second channel ([supplier.md](supplier.md#the-rot-vendor), [buyer.md](buyer.md#2-enroll-each-key-you-accept) for the role list). An HSM is best; [hsm-signing.md](../docs/hsm-signing.md) shows how.
4. **Agree the open points** in [agreement.md](agreement.md) with the buyer and your OSAT: which part and lots, which levels, key checks, which data the buyer receives, and what the pilot report may name.
5. **Run the first lot** as [supplier.md](supplier.md) describes, and hand the bundle over with the parts.

## What you get back

For every lot, `hslsa pilot measure` reports whether the buyer's check passed and why not if it failed, how long it took, which of your records' fields the buyer now holds, and the hours each party spent. Those reports are the pilot's result; [agreement.md](agreement.md) says what may be published from them, and each party approves it first.

The kit is shared under the [HSLSA Evaluation License](../LICENSE): use it inside your organization for this pilot, and do not pass it on. Report a security problem in the tool as [SECURITY.md](../SECURITY.md) says.
