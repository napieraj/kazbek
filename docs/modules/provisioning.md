# Module: provisioning (pairing / enrolment)

**Mode:** both
**Core dependency:** `TrustStore`, device connection
**Status:** planned (item 3 — RESEARCH-GRADE)

## Purpose
Bring a device from factory to enrolled-and-pinned, establishing the mutual-TLS
identity the core connection uses. No broadcast, no auto-discovery — deliberate,
auditable, manual bring-up.

## Flow
1. Operator points at the device by `.local` / IP (they already know where it
   is; the device does not advertise).
2. Key exchange; both sides derive a short confirmation value from both public
   keys + a nonce.
3. **Numeric comparison** (Bluetooth-SSP style): the value is shown on the
   controller and, on screen'd models (Comet Pro / X), on the device's
   touchscreen — operator confirms they match (defeats MITM: a man-in-the-middle
   yields two different values). Screenless models (RM1PE) use **paste-key**
   instead (trust arrives out-of-band).
4. On confirmation: device cert issued (via the `Signer`), server cert pinned on
   the device. From here, the core's pinned mutual TLS.

## The rule
The device never carries a reusable secret. Challenge-response and
authorization-to-act only; anything reusable that crosses an untrusted
intermediary is out. Pairing establishes trust *inward*; runtime is the pinned
dial-in.

## Threat model delta
Enrolment is the trust moment and it's deliberate + confirmed. A relay attacker
between device and controller produces a mismatched numeric value and is caught.
Re-enrolment (new cert) is a ticket, not a factory reset.

## Fallback
Screenless devices without a controller display: paste-key. Lost controller:
re-pair. Enrolment does not depend on any external service.

## Tests
- numeric-comparison match enrols; mismatch (simulated relay) refused
- paste-key path issues a cert without a display
- re-enrolment rotates the cert; the old cert is refused
