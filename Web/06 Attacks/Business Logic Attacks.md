---
title: "Business Logic Attacks"
aliases: []
tags: [web, w6, technique]
domain: web
phase: "W6"
type: technique
status: draft
pair: ""
updated: 2026-11-03
---
# Business Logic Attacks

> [!abstract] TL;DR
> Business-logic flaws violate application invariants even when requests are syntactically valid and individual endpoints appear authenticated.

> [!info] Agent scope
> Workflow invariants; state transitions; quantity and currency validation; replay; trust in client-derived state.

## Learn

```text
Teach business-logic failures as violations of domain invariants rather than
malformed syntax. Assume APIs, authorization, transactions, money, and state
machines. Model a checkout's actors, states, transitions, quantity/currency rules,
pricing authority, discount eligibility, replay handling, and irreversible effects.
Explain semantic validation across fields and services, confirmation binding,
idempotency keys bound to request identity, retry semantics, outbox patterns,
compensation, and concurrency limits. Review a secure synthetic checkout with
server-owned prices and exact decimal amounts. Provide complete regression tests,
evidence interpretation, primary references, and questions with separate answers.
No real payments, abuse sequences, bypasses, theft, scanning, or chained attacks.
Teach rather than author files; do not claim unexecuted tests passed.
```

## Cheatsheet

> [!important] Defensive scope
> This is a local state-machine review with synthetic prices and no payment system. It tests a secure implementation, not an abuse workflow.

### Invariants Before Endpoints

A syntactically valid request can still be invalid for the current actor, state, quantity, or commercial agreement. The root cause is often an unstated assumption between services or screens. Preconditions must be checked on the server at the transition that creates the effect, not only when the UI first displayed an option.

| Invariant | Authority | Enforcement point |
|---|---|---|
| Quantity is a bounded positive integer | Product rules | Before pricing and reservation |
| Price and discount are server-owned | Catalog/eligibility service | Quote calculation and confirmation |
| Currency matches the quote | Quote and settlement contract | Confirmation and payment submission |
| Only quoted orders can be confirmed | Persisted state machine | Atomic state transition |
| One intent produces one effect | Actor/order/idempotency binding | Same transaction as effect record |
| Retried key has same request | Stored request fingerprint | Before returning a cached outcome |

Do not use binary floating-point for money. Integer minor units are convenient but currency exponents differ; `Decimal` from strings supports explicit scale and rounding. Define when tax, discounts, and rounding occur, and who owns exchange rates. Never infer currency from a formatted symbol. A coupon is an entitlement with scope and lifetime, not a client-calculated subtraction.

### Workflow, Replay, and Distributed Effects

Represent allowed transitions explicitly. Confirmation should bind an immutable quote ID/version, amounts, currency, expiry, and actor; if the cart changes, issue a new quote. Idempotency is not permission: keys must be scoped to actor and operation, persisted with the result, and rejected on mismatched request reuse. A successful retry returns the prior outcome without creating a second effect.

A database transaction cannot atomically commit an unrelated remote payment by itself. Use a provider's idempotent operation, durable state, and an outbox/reconciliation process. Define compensation for partial failure rather than pretending every action can be rolled back. The in-memory lab is deliberately single-threaded; concurrency requires durable constraints and atomic updates.

Evidence: expected invariant, initial state, authorized actor, submitted business values, resulting state/effect count, and retry outcome. A strange status or sequence is not impact unless a rule was violated. Monitor impossible transitions, repeated conflicts, currency mismatches, and duplicate effects without recording payment credentials.

### Worked Contract and Versions

The Python 3.12 fixture uses `Decimal`, exact type checks, a fixed USD catalog, and a one-time quote transition. It omits tax, shipping, exchange rates, and expiration rather than implying universal checkout semantics. The discount is chosen by trusted server state, never by the confirmation input. Adapt product rules explicitly, not by accepting extra client fields.

## Defense

Write invariants before implementation; enforce them where effects commit. Recompute authoritative values, constrain transitions, bind confirmations, and store idempotency outcomes transactionally. Make retry and compensation semantics part of the API contract. Keep authorization independent of pricing and state validity.

## Labs

### Environment and Objectives

Python 3.12 stdlib; one file, no services or real financial activity. Review a proposal that trusts client totals and treats confirmation retries as new orders. The secure replacement computes a quote and binds confirmation to its amount/currency. All fixtures are inline.

### File: test_example.py

```python
from decimal import Decimal
import unittest


class Checkout:
	def __init__(self):
		self.state = "draft"
		self.total = None
		self.currency = "USD"
		self.receipts = {}
		self.effects = 0

	def quote(self, quantity, eligible_discount=False):
		if self.state != "draft":
			raise ValueError("transition")
		if type(quantity) is not int or not 1 <= quantity <= 5:
			raise ValueError("quantity")
		if type(eligible_discount) is not bool:
			raise ValueError("server eligibility")
		total = Decimal("12.50") * quantity
		if eligible_discount:
			total *= Decimal("0.90")
		self.total = total.quantize(Decimal("0.01"))
		self.state = "quoted"
		return self.total

	def confirm(self, key, amount, currency):
		if type(key) is not str or not 1 <= len(key) <= 80:
			raise ValueError("idempotency key")
		if type(amount) is not Decimal or not amount.is_finite():
			raise ValueError("amount")
		fingerprint = (amount, currency)
		if key in self.receipts:
			saved, receipt = self.receipts[key]
			if saved != fingerprint:
				raise ValueError("key reuse mismatch")
			return receipt
		if self.state != "quoted" or amount != self.total or currency != self.currency:
			raise ValueError("quote mismatch or transition")
		receipt = "synthetic-receipt-1"
		self.receipts[key] = (fingerprint, receipt)
		self.effects += 1
		self.state = "confirmed"
		return receipt


class WorkflowTests(unittest.TestCase):
	def test_quote_and_retry(self):
		order = Checkout()
		total = order.quote(2, eligible_discount=True)
		self.assertEqual(total, Decimal("22.50"))
		first = order.confirm("intent-1", total, "USD")
		self.assertEqual(order.confirm("intent-1", total, "USD"), first)
		self.assertEqual(order.effects, 1)

	def test_invalid_quantity_and_sequence(self):
		for quantity in [0, -1, True, 6, 1.5]:
			order = Checkout()
			with self.assertRaises(ValueError):
				order.quote(quantity)
			self.assertEqual(order.state, "draft")
		order = Checkout()
		with self.assertRaises(ValueError):
			order.confirm("intent-1", Decimal("12.50"), "USD")
		self.assertEqual(order.effects, 0)

	def test_currency_amount_and_repeated_quote(self):
		order = Checkout()
		total = order.quote(1)
		for amount, currency in [(total, "EUR"), (Decimal("1.00"), "USD")]:
			with self.assertRaises(ValueError):
				order.confirm("intent-1", amount, currency)
		with self.assertRaises(ValueError):
			order.quote(1, eligible_discount=True)
		self.assertEqual(order.effects, 0)
		order.confirm("intent-1", total, "USD")
		with self.assertRaises(ValueError):
			order.confirm("intent-1", Decimal("1.00"), "USD")
		with self.assertRaises(ValueError):
			order.confirm("intent-2", total, "USD")
		self.assertEqual(order.effects, 1)


if __name__ == "__main__":
	unittest.main()
```

### Commands, Hints, and Separate Solution

```powershell
py -3.12 -m unittest -v test_example
```

Use `python3.12` on other platforms. Hint: distinguish a retry of the same intent from a second intent after confirmation. Why must a repeated key with different values fail rather than return success?

Solution: quote calculation owns the price; confirmation requires matching amount/currency and a valid state; replay returns the stored receipt only for the same fingerprint. Expected: three tests pass and effect count never exceeds one. `eligible_discount` is trusted server input in this fixture; exposing it directly to a client would violate the design. Actor scoping, persistence, expiration, and distributed transactions remain application work.

### Verification, Troubleshooting, and Cleanup

No tests ran during authoring. Run beside the file and do not shadow `decimal.py`. Decimal inputs must be constructed from strings as shown. All state is in memory; remove the disposable directory afterward. The tests validate the printed product rules, not a real checkout or concurrent service.

- [ ] Local Business Logic Attacks exercise: Review price, currency, state, and replay invariants.
- [ ] Boundary check: Run secure transition and single-effect regressions.
- [ ] Record the observed result, relevant version, and a retest after applying the control.

## Related

- [[Web Roadmap#W6 Attacks|W6 Attacks]]

## References

- [Python Decimal arithmetic](https://docs.python.org/3.12/library/decimal.html)
- [OWASP Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests)
