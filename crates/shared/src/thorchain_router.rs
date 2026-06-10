//! `THORChain` Router v6.1 call ABI — ONE definition shared between
//! the EVM redeem executor (builds the calldata) and the signer-daemon
//! EVM gate (decodes the calldata and binds it to the certified
//! intent, CTD-1 / `DL-CTD-2`). A single source of truth means the
//! builder and the verifier can never drift on the ABI.

use alloy_sol_types::sol;

sol! {
    /// `THORChain` Router v6.1 `depositWithExpiry`. Same ABI on every
    /// Phase 3.2 EVM chain (Bifrost deploys the identical Router on
    /// ETH / BSC / AVAX / BASE / POL).
    function depositWithExpiry(
        address payable vault,
        address asset,
        uint256 amount,
        string memo,
        uint256 expiry
    ) external payable;
}
