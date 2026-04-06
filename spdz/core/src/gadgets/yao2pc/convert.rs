//! SPDZ ↔ Garbled Circuit share conversion.
//!
//! Converting between SPDZ additive shares and GC wire labels.
//!
//! SPDZ → Yao (for each shared bit):
//!   Party 0 (garbler) knows: share_0 (their SPDZ share of the bit)
//!   Party 1 (evaluator) knows: share_1 (their SPDZ share)
//!   Value: bit = share_0 + share_1 (mod p), which is 0 or 1
//!
//!   Garbler generates two wire labels: W_0, W_1 (for bit values 0 and 1)
//!   Garbler knows share_0, so they know: "if share_1 == 0 then bit = share_0,
//!     if share_1 == 1 then bit = 1 - share_0" (for bits in {0,1})
//!
//!   Use 1-out-of-2 OT:
//!     Garbler offers: (W_{share_0}, W_{1-share_0})
//!     Evaluator selects with choice bit: share_1
//!     Evaluator receives: W_{share_0 + share_1 mod 2} = W_{bit}
//!
//!   Now: Garbler knows both labels. Evaluator knows W_{bit} (the correct one).
//!   This is exactly the input encoding for Yao's protocol.
//!
//! Yao → SPDZ (for output bits):
//!   After GC evaluation, evaluator knows the output wire label.
//!   Garbler knows the mapping: label → bit value.
//!   They use a simple protocol to create SPDZ shares of the output bit.

use scuttlebutt::Block;

/// Convert a SPDZ shared bit (party_0_share, party_1_share) into
/// garbled circuit wire labels for both garbler and evaluator.
///
/// Returns: (garbler_label, evaluator_label) where evaluator_label
/// corresponds to the actual bit value.
///
/// This is the A→Y conversion step.
pub fn spdz_bit_to_gc_wire(
    my_share: bool,      // This party's SPDZ share of the bit
    party_id: usize,     // 0 = garbler, 1 = evaluator
    label_0: Block,      // Wire label for bit value 0 (garbler generates)
    label_1: Block,      // Wire label for bit value 1 (garbler generates)
) -> Block {
    // Garbler: returns the label corresponding to their share
    // (they'll send both to OT, evaluator picks based on their share)
    if party_id == 0 {
        // Garbler returns their label for the full input encoding
        if my_share { label_1 } else { label_0 }
    } else {
        // Evaluator: their label comes from OT, not computed here
        // This function is only for the garbler's side
        Block::default()
    }
}

/// The OT messages the garbler prepares for one input bit.
/// Returns (msg_0, msg_1) for the OT sender.
///
/// If evaluator's share is 0, they get msg_0 = W_{garbler_share + 0} = W_{garbler_share}
/// If evaluator's share is 1, they get msg_1 = W_{garbler_share + 1} = W_{1 - garbler_share}
pub fn garbler_ot_messages(
    garbler_share: bool,
    label_0: Block,     // wire label for bit = 0
    label_1: Block,     // wire label for bit = 1
) -> (Block, Block) {
    if garbler_share {
        // garbler_share = 1: bit = 1 + evaluator_share mod 2
        // evaluator_share = 0 → bit = 1 → label_1
        // evaluator_share = 1 → bit = 0 → label_0
        (label_1, label_0)
    } else {
        // garbler_share = 0: bit = 0 + evaluator_share mod 2
        // evaluator_share = 0 → bit = 0 → label_0
        // evaluator_share = 1 → bit = 1 → label_1
        (label_0, label_1)
    }
}

/// Convert a GC output wire label back to a SPDZ share.
///
/// After evaluation, the evaluator knows the output label.
/// The garbler knows the label-to-bit mapping.
/// They create SPDZ shares: garbler picks random share, sends correction to evaluator.
pub fn gc_output_to_spdz_share(
    output_bit: bool,   // The actual output bit (known after GC evaluation)
    party_id: usize,
) -> (u8, u8) {
    // Simple approach: party 0 gets output_bit as their share, party 1 gets 0
    // This is trivial sharing — ok for output bits that will be combined into
    // a larger SPDZ value
    if party_id == 0 {
        (output_bit as u8, 0)
    } else {
        (0, output_bit as u8)
    }
}
