# Shared secret-core integration

Canonical method: SCAR-MLKEM. This is an isolated implementation experiment, not a final performance result.

The only production changes from the pinned packed controller are S payload 1152 bytes (1216 with header), exact full-key composition on a hit, prefix extraction on admission, and the previously qualified shared NEON public library. Policy, forecasts, masks, thresholds, pending/publication, non-renewing expiry, erase/readback and no-retention path remain unchanged. All applicable controls receive the same representation and backend.

A hit obtains S by the existing context/generation-checked lookup and combines it with that context's immutable enrollment. The existing generation and rotation fixtures still apply. The harness has static enrollment during one process: dynamic replacement of enrolled keys is not implemented or claimed. The controller rotation test covers invalidation, not a deployed key-import protocol.

`Event.reconstruction` now includes hit composition as well as miss expansion. Full 2400-byte scratch is still cleared after every request. Persistent seed storage is unchanged. Secret core remains sensitive. No standard key length, security parameter or ciphertext is reduced.

Independent placement and baseline-parity fixtures use identical changed geometry. Saturation tests fill residual space with secret entries before asserting lack of space; they must not assume the old allocation sizes. Public fake payloads only run on Mac. Native integrated crypto/lifecycle remains a separate gate, followed by fresh common calibration including hit composition and shorter copy/erase. Old cost coefficients are only finite functional inputs, never performance calibration for this source. No timing budget is spent by qualification.
