# NL/ID API SNI route

This is the independently scoped production repair for the existing Netherlands
and Indonesia backbone peers. Their direct exit-to-primary API path loses SYN
replies on individual flows. The retained DE/PL and FI/US routes remain separate.

The controller binds 10.77.0.18:19445 and selects only new TCP/443 flows from
10.77.2.1 and 10.77.0.13 to 193.247.73.15. Exact API SNI names use the existing
82.208.22.95 ingress; other SNI keeps the original destination. Encrypted bytes,
TLS certificates and HTTP requests are passed through unchanged. There is no
HTTP retry or TLS termination in this listener.

Install the exact controller/policy into the scope named in controller.py only
after namespace validation generates policy-templates.json. Existing binary and
loader hashes are pinned. `arm` starts a 900-second rollback timer; `apply`
starts the independent unit. `retain` requires a private acceptance.json with
20 fresh, fully verified connections per node and matching API request receipts.
It enables the unit and retires the rollback timer. `backout-retained` removes
only this scope's verified NAT/filter/unit. No conntrack flush is performed.

Run `python3 -m unittest discover -s ops/api-sni-nl-id -p 'test_*.py'`.
The Moscow relay outage is separate and is not fixed by this policy.
