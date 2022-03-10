
// Construct the final covenant script, including the state and quine self-reference
fn RoyaltyCovenant($BTC, $creator_pk, $royalty, $owner_pk, $price) {
  $script = RoyaltyCovenantBase($BTC, $creator_pk, $royalty);
  $state = `$price $owner_pk`;

  // Final script: <push state> <push own tapscript> <own tapscript>
  `$state bytes($script) $script`
}

// Main covenant script
fn RoyaltyCovenantBase($BTC, $creator_pk, $royalty) = `
  // State (injected by RoyaltyCovenant())
    // <price>
    // <owner_pk>

  OP_TOALTSTACK // send <own tapscript> to altstack (injected by RoyaltyCovenant())

  // Stack: [call type params] <output key prefix> <call type byte> -- <current price> <current owner key>

  // Some sanity checks
    requireRbf
    1 OP_CSV OP_DROP // prevent unconfirmed tx chain

  // Dispatch call type to the call handler script
    OP_ROT // bring call type byte to the top
    select([
      /* 0x00: */ buyCall($BTC, $creator_pk, $royalty),
      /* 0x01: */ setPriceCall,
      /* 0x02: */ burnCall($creator_pk)
    ])

  // Stack: <output key prefix> -- <new owner key> <new price>

  // Validate new state
    OP_SIZE 8 OP_EQUALVERIFY
    OP_SWAP
    OP_SIZE 32 OP_EQUALVERIFY
    // Stack: <output key prefix> -- <price> <owner key>

  // Build new state blob (PUSHBYTES_8 <price> PUSHBYTES_20 <owner key>)
    buildStateBlob
    // Stack: <output key prefix> -- <state blob>

  // Build the expected destination tapscript (<new state> || <push(own tapscript)> || <own tapscript>)
    OP_FROMALTSTACK // bring <own tapscript>
    buildScriptBlob
    // Stack: <output key prefix> -- <script blob>

  // Compute the taproot merkle root hash (a single leaf script) and the tweak hash
    elementsPushTapLeaf
    H_POINT OP_TUCK
    // Stack: <output key prefix> -- <H_POINT> <leaf hash> <H_POINT>
    elementsPushTapTweak
    // Stack: <output key prefix> -- <H_POINT> <tweak hash>

  // Enforce recursive covenant at output #0 with the new state/script
    // Check that the input asset/amount was transferred to output #0 in full (typically 1 token)
      checkSameValue(OP_PUSHCURRENTINPUTINDEX, 0)

    // Push the pubkey used by output #0, concatenated with the <output key prefix>
      OP_ROT // bring <output key prefix>
      0 inspectOutSpkVer(1)
      OP_CAT
      // Stack: <H_POINT> <tweak hash> <prefixed output pubkey>

    // Verify the destination output matches the expected tapscript tweaked from H_POINT
      OP_SWAP OP_ROT
      // Stack: <prefixed output pubkey> <tweak hash> <H_POINT>
      OP_TWEAKVERIFY

  true
`;

// Initialize the contract with its initial state (the creator as the initial owner and
// with sales disabled until a price is set)
fn RoyaltyCovenantInit($BTC, $creator_pk, $royalty) =
  RoyaltyCovenant($BTC, $creator_pk, $royalty, $creator_pk, MAX_NUMBER);


//
// Call methods
//
// State transition scripts, expected to consume the top 2 stack elements as the current state, consume
// the witness stack elements for the call type, and push the new state onto the stack.
//

// Buy call (0x00)
// stack in: <new owner key> <output key prefix> -- <current price> <current owner key>
// stack out: <output key prefix> -- <new owner key> <new price (MAX)>
fn buyCall($BTC, $creator_pk, $royalty) = `

  // Verify payment output to current owner at index #1
    // Is L-BTC
      1 inspectExplicitOutAsset
      $BTC OP_DUP OP_TOALTSTACK // keep $BTC around in the altstack, we'll need it again shortly
      OP_EQUALVERIFY

    // Pays to current owner key (pop the owner key off)
      1 inspectOutSpkVer(1)
      OP_EQUALVERIFY

    // Pays the correct amount
      OP_DUP // keep a copy of the price for later user
      1 inspectExplicitOutValue
      OP_EQUALVERIFY

  // Verify royalty payment output to creator at index #2
    // Is L-BTC
      2 inspectExplicitOutAsset
      OP_FROMALTSTACK // get L-BTC asset id
      OP_EQUALVERIFY

    // Pays to creator key
      2 inspectOutSpkVer(1)
      $creator_pk
      OP_EQUALVERIFY

    // Amount paid matches the $royalty setting
      // Calculate royalty payment amount (price/$royalty, e.g. 20 for 5%)
          le64($royalty)
          div64VerifyFloor
          // TODO minimum dust amount
      2 inspectExplicitOutValue
      OP_EQUALVERIFY

  // Stack: <new owner key> <output key prefix> --

  // Prepare new state
    // Bring new owner key (from the witness stack)
      OP_SWAP
    // Set price to MAX (disallow sales until a new price is set by the new owner)
      MAX_NUMBER
`;

// Set price call (0x01)
// stack in: <new price> <owner sig> <output key prefix> -- <current price> <current owner key>
// stack out: <output key prefix> -- <owner key (unchanged)> <new price>
setPriceCall = `
  OP_NIP // drop old price

  // Verify signature by current owner
    OP_DUP // keep current owner key to construct the state
    3 OP_ROLL OP_SWAP // bring sig before key
    OP_CHECKSIGVERIFY

  // Stack: <new price> <output key prefix> -- <owner key>

  // Prepare new state
    // (owner key is already here)
    // Bring new price to top (from the witness stack)
      OP_ROT
`;

// Burn call (0x02)
// stack in: <creator sig> <output key prefix> -- <current price> <current owner key>
// stack out: <output key prefix> -- <owner key (H_POINT)> <new price (max)>
fn burnCall($creator_pk) = `
  OP_2DROP // drop current state, we don't need it

  // Verify signature by creator
    OP_SWAP // bring sig from witness stack
    $creator_pk
    OP_CHECKSIGVERIFY

  // Stack: <output key prefix>

  // Prepare new state
    // Use point with unknown discrete logarithm as the new owner pubkey (no owner)
      H_POINT
    // Set price to MAX (disallow sales forever)
      MAX_NUMBER
`;

//
// Utilities for constructing the recursive covenant
//

// Build the state blob as script bytes
// stack in: <price> <owner pubkey>
// stack out: <state blob: 0x08 || price || 0x20 || owner>
buildStateBlob = `
  // Prefix <owner pubkey> with PUSHBYTES_32
    32 OP_SWAP OP_CAT
  // Concat with <price>, prefix with PUSHBYTES_8
    OP_CAT
    8 OP_SWAP OP_CAT
  // Final blob: OP_PUSHBYTES_8 <price> OP_PUSHBYTES_32 <owner>
`;

// Build the final script blob, including the state and quine
// stack in: <state blob> <own tapscript>
// stack out: <final script: state || push(own_tapscript) || own_tapscript>
buildScriptBlob = `
  OP_DUP

  // PUSH for <own tapscript>
    // Get the push opcode bytes for <own tapscript>'s length
      pushDataPrefix
    // Merge PUSH opcode and <own tapscript> blob
      OP_SWAP OP_CAT

  // Append <own tapscript> code (actual opcodes, not data push)
    OP_SWAP OP_CAT

  // Prepend <state blob>
    OP_CAT

  // Final blob: push(<price>) push(<owner>) push(<own tapscript as data>) <own tapscript as code>
`;

RoyaltyCovenantInit(TLBTC, 0xcbc28b82ddfa91c5c0bce5dcaf2d1ded79cbf9738be278e97465d389cc7423a3, 20)