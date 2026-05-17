//! MLS group state and message processing (RFC 9420).
//!
//! Wraps `openmls`. See DESIGN.md §6. All conversations — including 1-on-1
//! DMs — are modelled as MLS groups, so this module is the single source of
//! truth for "send a message to N people."
//!
//! Notable design constraints from §6.5: every application message carries
//! a signature from the long-term credential, i.e. Onyx v1 is **not**
//! deniable. The wire envelope reserves space to add a deniable mode later
//! without a protocol break.
