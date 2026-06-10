# chio-weights

`chio-weights` is Chio's model-card surface. Signed model cards bind a
provider's `(weights_hash, allowed_capability_set, banned_tools,
training_data_class)` to a cosign-signed envelope, and the kernel refuses to
bind a provider whose loaded weights or requested scopes do not match the card.
The crate also ships a cosign bundle helper. Every public method that returns
`Ok(_)` carries a real trust guarantee; the surface fails closed otherwise.

Use this crate to author, sign, and verify model cards, and to enforce
weights-to-capability binding at kernel bind time (`chio bind --card`).
