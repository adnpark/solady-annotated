// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Simple ERC20 + EIP-2612 implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/tokens/ERC20.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol)
///
/// @dev Note:
/// - The ERC20 standard allows minting and transferring to and from the zero address,
///   minting and transferring zero tokens, as well as self-approvals.
///   For performance, this implementation WILL NOT revert for such actions.
///   Please add any checks with overrides if desired.
/// - The `permit` function uses the ecrecover precompile (0x1).
///
/// If you are overriding:
/// - NEVER violate the ERC20 invariant:
///   the total sum of all balances must be equal to `totalSupply()`.
/// - Check that the overridden function is actually used in the function you want to
///   change the behavior of. Much of the code has been manually inlined for performance.
abstract contract ERC20 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The total supply has overflowed.
    error TotalSupplyOverflow();

    /// @dev The allowance has overflowed.
    error AllowanceOverflow();

    /// @dev The allowance has underflowed.
    error AllowanceUnderflow();

    /// @dev Insufficient balance.
    error InsufficientBalance();

    /// @dev Insufficient allowance.
    error InsufficientAllowance();

    /// @dev The permit is invalid.
    error InvalidPermit();

    /// @dev The permit has expired.
    error PermitExpired();

    /// @dev The allowance of Permit2 is fixed at infinity.
    error Permit2AllowanceIsFixedAtInfinity();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when `amount` tokens is transferred from `from` to `to`.
    event Transfer(address indexed from, address indexed to, uint256 amount);

    /// @dev Emitted when `amount` tokens is approved by `owner` to be used by `spender`.
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /// @dev `keccak256(bytes("Transfer(address,address,uint256)"))`.
    uint256 private constant _TRANSFER_EVENT_SIGNATURE =
        0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;

    /// @dev `keccak256(bytes("Approval(address,address,uint256)"))`.
    uint256 private constant _APPROVAL_EVENT_SIGNATURE =
        0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The storage slot for the total supply.
    uint256 private constant _TOTAL_SUPPLY_SLOT = 0x05345cdf77eb68f44c;

    /// @dev The balance slot of `owner` is given by:
    /// ```
    ///     mstore(0x0c, _BALANCE_SLOT_SEED)
    ///     mstore(0x00, owner)
    ///     let balanceSlot := keccak256(0x0c, 0x20)
    /// ```
    uint256 private constant _BALANCE_SLOT_SEED = 0x87a211a2;

    /// @dev The allowance slot of (`owner`, `spender`) is given by:
    /// ```
    ///     mstore(0x20, spender)
    ///     mstore(0x0c, _ALLOWANCE_SLOT_SEED)
    ///     mstore(0x00, owner)
    ///     let allowanceSlot := keccak256(0x0c, 0x34)
    /// ```
    uint256 private constant _ALLOWANCE_SLOT_SEED = 0x7f5e9f20;

    /// @dev The nonce slot of `owner` is given by:
    /// ```
    ///     mstore(0x0c, _NONCES_SLOT_SEED)
    ///     mstore(0x00, owner)
    ///     let nonceSlot := keccak256(0x0c, 0x20)
    /// ```
    uint256 private constant _NONCES_SLOT_SEED = 0x38377508;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `(_NONCES_SLOT_SEED << 16) | 0x1901`.
    uint256 private constant _NONCES_SLOT_SEED_WITH_SIGNATURE_PREFIX = 0x383775081901;

    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    bytes32 private constant _DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev `keccak256("1")`.
    /// If you need to use a different version, override `_versionHash`.
    bytes32 private constant _DEFAULT_VERSION_HASH =
        0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    /// @dev `keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")`.
    bytes32 private constant _PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    /// @dev The canonical Permit2 address.
    /// For signature-based allowance granting for single transaction ERC20 `transferFrom`.
    /// To enable, override `_givePermit2InfiniteAllowance()`.
    /// [Github](https://github.com/Uniswap/permit2)
    /// [Etherscan](https://etherscan.io/address/0x000000000022D473030F116dDEE9F6B43aC78BA3)
    address internal constant _PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       ERC20 METADATA                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the name of the token.
    function name() public view virtual returns (string memory);

    /// @dev Returns the symbol of the token.
    function symbol() public view virtual returns (string memory);

    /// @dev Returns the decimals places of the token.
    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERC20                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the amount of tokens in existence.
    function totalSupply() public view virtual returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := sload(_TOTAL_SUPPLY_SLOT)
        }
    }

    /// @dev Returns the amount of tokens owned by `owner`.
    function balanceOf(address owner) public view virtual returns (uint256 result) {
        // -------------------------------------------
        // 1. Load the balance from storage.
        // -------------------------------------------
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x0c, _BALANCE_SLOT_SEED) // Store _BALANCE_SLOT_SEED at 0x0c(12 in decimal)
            mstore(0x00, owner) // Store owner at 0x00
            // after two mstore operations, the memory layout is as follows:
            // | 0x00(0) - 0x0b(11) | First 12 bytes of owner (padded with zeros)
            // | 0x0c(12) - 0x1f(31) | Last 20 bytes of owner (actual owner address)
            // | 0x20(32) - 0x2b(43) | Remaining 12 bytes of _BALANCE_SLOT_SEED(12 bytes)
            result := sload(keccak256(0x0c, 0x20)) // keccak256 starts at 0x0c and takes 32 bytes(0x20 = 32 bytes)
                // purpose of arrangement: keccak256(abi.encodePacked(key(owner), mapping_slot))
        }
    }

    /// @dev Returns the amount of tokens that `spender` can spend on behalf of `owner`.
    function allowance(address owner, address spender)
        public
        view
        virtual
        returns (uint256 result)
    {
        // -------------------------------------------
        // 1. If Permit2 is given infinite allowance and spender is Permit2, return type(uint256).max.
        // -------------------------------------------
        if (_givePermit2InfiniteAllowance()) {
            if (spender == _PERMIT2) return type(uint256).max;
        }
        // -------------------------------------------
        // 2. Otherwise, load the allowance from storage.
        // -------------------------------------------
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, spender) // Store spender at 0x20
            mstore(0x0c, _ALLOWANCE_SLOT_SEED) // Store _ALLOWANCE_SLOT_SEED at 0x0c
            mstore(0x00, owner) // Store owner at 0x00
            // after three mstore operations, the memory layout is as follows:
            // | 0x00(0) - 0x0b(11) | First 12 bytes of owner (padded with zeros)
            // | 0x0c(12) - 0x1f(31) | Last 20 bytes of owner (actual owner address)
            // | 0x20(32) - 0x2b(43) | Remaining 12 bytes of _ALLOWANCE_SLOT_SEED(12 bytes)
            // | 0x2c(44) - 0x3f(63) | Last 20 bytes of spender (actual spender address)
            result := sload(keccak256(0x0c, 0x34)) // keccak256 starts at 0x0c(12) and takes 52 bytes(0x34 = 52 bytes)
                // purpose of arrangement: keccak256(abi.encodePacked(key(owner), mapping_slot, spender))
        }
    }

    /// @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
    ///
    /// Emits a {Approval} event.
    function approve(address spender, uint256 amount) public virtual returns (bool) {
        // -------------------------------------------------------------------
        // 1. If `_givePermit2InfiniteAllowance()` is true and `spender == _PERMIT2`,
        //    we must ensure `amount == type(uint256).max`. Otherwise, revert.
        // -------------------------------------------------------------------
        if (_givePermit2InfiniteAllowance()) {
            /// @solidity memory-safe-assembly
            assembly {
                // If `spender == _PERMIT2 && value != type(uint256).max`.
                //
                // The condition:
                //   if iszero(or(xor(shr(96, shl(96, spender)), _PERMIT2), iszero(not(value)))) {
                //
                // breaks down as follows:
                //
                //   1) shl(96, spender)  => shift spender left 96 bits
                //   2) shr(96, ...)      => shift right 96 bits
                //                         => effectively a no-op for a clean 20-byte address,
                //                            but ensures top/bottom bits are zeroed
                //   3) xor( ..., _PERMIT2 )
                //      => 0 if the 20-byte part of `spender` is exactly `_PERMIT2`
                //   4) not(value)        => bitwise NOT of `value`.
                //      => 0 if `value == type(uint256).max`,
                //         nonzero otherwise
                //   5) iszero( not(value) )
                //      => true (1) if `value == type(uint256).max`; false (0) otherwise
                //   6) or( <X>, <Y> )
                //      => true if either <X> or <Y> is nonzero
                //   7) iszero( or(...) )
                //      => condition is `true` if BOTH <X> and <Y> are zero
                //
                // So overall, "if iszero(or(xor(...), iszero(not(value)))))" means:
                //   => if (xor(...) == 0) AND (iszero(not(value)) == 0)
                //   => if (spender is exactly _PERMIT2) AND (value != type(uint256).max)
                //
                // => revert with "Permit2AllowanceIsFixedAtInfinity()"
                if iszero(or(xor(shr(96, shl(96, spender)), _PERMIT2), iszero(not(amount)))) {
                    mstore(0x00, 0x3f68539a) // `Permit2AllowanceIsFixedAtInfinity()`.
                    revert(0x1c, 0x04)
                }
            }
        }
        /// @solidity memory-safe-assembly
        assembly {
            // -------------------------------------------------------------------
            // 2. Compute the storage slot where allowance[msg.sender][spender] is stored,
            //    and then store `amount` in it.
            // -------------------------------------------------------------------
            // Compute the allowance slot and store the amount.
            mstore(0x20, spender) // Store spender at 0x20
            mstore(0x0c, _ALLOWANCE_SLOT_SEED) // Store _ALLOWANCE_SLOT_SEED at 0x0c
            mstore(0x00, caller()) // Store caller at 0x00
            // after three mstore operations, the memory layout is as follows:
            // | 0x00(0) - 0x0b(11) | First 12 bytes of caller (padded with zeros)
            // | 0x0c(12) - 0x1f(31) | Last 20 bytes of caller (actual caller address)
            // | 0x20(32) - 0x2b(43) | Remaining 12 bytes of _ALLOWANCE_SLOT_SEED(12 bytes)
            // | 0x2c(44) - 0x3f(63) | Last 20 bytes of spender (actual spender address)
            sstore(keccak256(0x0c, 0x34), amount) // store amount at the slot
                // keccak256 starts at 0x0c(12) and takes 52 bytes(0x34 = 52 bytes)
                // purpose of arrangement: keccak256(abi.encodePacked(key(owner), mapping_slot, spender))
            // -------------------------------------------------------------------
            // 3. Emit the Approval event: log3(data, data_size, signature, topic1, topic2).
            //    We store `amount` in memory at 0x00, and `caller()` / `spender` become topics.
            // -------------------------------------------------------------------
            mstore(0x00, amount) // store amount at 0x00
            log3(0x00, 0x20, _APPROVAL_EVENT_SIGNATURE, caller(), shr(96, mload(0x2c)))
        }
        return true;
    }

    /// @dev Transfer `amount` tokens from the caller to `to`.
    ///
    /// Requirements:
    /// - `from` must at least have `amount`.
    ///
    /// Emits a {Transfer} event.
    function transfer(address to, uint256 amount) public virtual returns (bool) {
        // -------------------------------------------------------------------
        // 1. Optional hook that can be overridden to include logic
        //    like fee, blocklists, or other checks before transferring.
        // -------------------------------------------------------------------
        _beforeTokenTransfer(msg.sender, to, amount);
        /// @solidity memory-safe-assembly
        assembly {
            // -------------------------------------------------------------------
            // 2. Compute storage slot for `from` (i.e., msg.sender)'s balance.
            // -------------------------------------------------------------------
            mstore(0x0c, _BALANCE_SLOT_SEED)
            mstore(0x00, caller())
            // after two mstore operations, the memory layout is as follows:
            // | 0x00(0) - 0x0b(11) | First 12 bytes of caller (padded with zeros)
            // | 0x0c(12) - 0x1f(31) | Last 20 bytes of caller (actual caller address)
            // | 0x20(32) - 0x2b(43) | Remaining 12 bytes of _BALANCE_SLOT_SEED(12 bytes)
            let fromBalanceSlot := keccak256(0x0c, 0x20) // keccak256 starts at 0x0c(12) and takes 32 bytes(0x20 = 32 bytes)
                // purpose of arrangement: keccak256(abi.encodePacked(key(owner), mapping_slot))
            let fromBalance := sload(fromBalanceSlot) // load the balance from the slot
            // Revert if insufficient balance.
            // -------------------------------------------------------------------
            // 3. Check if `fromBalance` >= `amount`. If not, revert.
            // -------------------------------------------------------------------
            if gt(amount, fromBalance) {
                // if amount is greater than the balance
                mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                revert(0x1c, 0x04) // take 4 bytes at 0x1c(28) - 0x1f(31), which is the error message(0xf4d678b8)
            }
            // -------------------------------------------------------------------
            // 4. Subtract `amount` from `fromBalance` and store it back.
            // -------------------------------------------------------------------
            sstore(fromBalanceSlot, sub(fromBalance, amount))
            // -------------------------------------------------------------------
            // 5. Compute the balance slot for `to`.
            // -------------------------------------------------------------------
            mstore(0x00, to) // store `to` at 0x00
            // after one mstore operation, the memory layout is as follows:
            // | 0x00(0) - 0x0b(11) | First 12 bytes of `to` (padded with zeros)
            // | 0x0c(12) - 0x1f(31) | Last 20 bytes of `to` (actual `to` address)
            // | 0x20(32) - 0x2b(43) | Remaining 12 bytes of _BALANCE_SLOT_SEED(12 bytes)
            let toBalanceSlot := keccak256(0x0c, 0x20) // keccak256 starts at 0x0c(12) and takes 32 bytes(0x20 = 32 bytes)
                // purpose of arrangement: keccak256(abi.encodePacked(key(`to`), mapping_slot))
            // -------------------------------------------------------------------
            // 6. Load `to`'s balance, add `amount`, store new balance.
            //    No overflow check here because total supply does not exceed uint256.max.
            // -------------------------------------------------------------------
            sstore(toBalanceSlot, add(sload(toBalanceSlot), amount))
            // -------------------------------------------------------------------
            // 7. Emit the Transfer event:
            //    We store `amount` in memory at 0x20, then call log3 with
            //    - topic #0 = Transfer event signature
            //    - topic #1 = from (caller())
            //    - topic #2 = to
            // -------------------------------------------------------------------
            mstore(0x20, amount)
            log3(0x20, 0x20, _TRANSFER_EVENT_SIGNATURE, caller(), shr(96, mload(0x0c)))
        }
        _afterTokenTransfer(msg.sender, to, amount);
        return true;
    }

    /// @dev Transfers `amount` tokens from `from` to `to`.
    ///
    /// Note: Does not update the allowance if it is the maximum uint256 value.
    ///
    /// Requirements:
    /// - `from` must at least have `amount`.
    /// - The caller must have at least `amount` of allowance to transfer the tokens of `from`.
    ///
    /// Emits a {Transfer} event.
    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        // -------------------------------------------
        // 1. Call a hook that can be overridden to run code before every transfer.
        //    Common use-cases include tax, fee, or blocklisting logic.
        // -------------------------------------------
        _beforeTokenTransfer(from, to, amount);
        // -------------------------------------------
        // 2. If _givePermit2InfiniteAllowance() is true, it means Permit2
        //    (the address 0x0000...022D473...) is given infinite allowance.
        //    The code below has two branches for performance reasons.
        //    The logic is effectively the same in both branches, except that
        //    if Permit2 has infinite allowance, we skip some checks.
        // -------------------------------------------
        /// Code duplication is for zero-cost abstraction if possible.
        if (_givePermit2InfiniteAllowance()) {
            /// @solidity memory-safe-assembly
            assembly {
                // -------------------------------------------
                // SHIFTING AND PREPARATION
                // -------------------------------------------
                // 3. Shift `from` left by 96 bits so that the 160-bit address
                //    sits in the high part of the 256-bit word.
                let from_ := shl(96, from)
                // 4. Check if msg.sender is NOT Permit2.
                //   If it's not Permit2, we must enforce allowance checks.
                if iszero(eq(caller(), _PERMIT2)) {
                    // -------------------------------------------
                    // ALLOWANCE CHECKS
                    // -------------------------------------------
                    // 5. Store `caller()` at memory offset 0x20 (32 in decimal).
                    //    We'll feed this chunk of memory into keccak256 to get
                    //    the correct storage slot for the allowance.
                    // Compute the allowance slot and load its value.
                    mstore(0x20, caller())
                    // 6. Combine the `from_` address (shifted above)
                    //    with the _ALLOWANCE_SLOT_SEED. Store it at offset 0x0c (12).
                    //    Memory layout so far (important for the keccak256 call):
                    //      [0x00..0x0b] = empty/unused
                    //      [0x0c..0x1f] = from_ + allowance slot seed
                    //      [0x20..0x3f] = caller()
                    mstore(0x0c, or(from_, _ALLOWANCE_SLOT_SEED))
                    // 7. Compute the keccak256 hash over the 52 bytes [0x0c..0x3f].
                    //    This produces the unique storage slot for (from, caller) allowance.
                    let allowanceSlot := keccak256(0x0c, 0x34)
                    // 8. Load the current allowance from that storage slot.
                    let allowance_ := sload(allowanceSlot)
                    // 9. If allowance_ != type(uint256).max, we must do a proper allowance check.
                    //    "not(allowance_)" is 0 if allowance_ == 0xFFFF... (max uint).
                    if not(allowance_) {
                        // 10. Revert if `amount` > `allowance_`.
                        if gt(amount, allowance_) {
                            mstore(0x00, 0x13be252b) // `InsufficientAllowance()`.
                            revert(0x1c, 0x04)
                        }
                        // 11. Subtract `amount` from `allowance_` and store the updated allowance.
                        sstore(allowanceSlot, sub(allowance_, amount))
                    }
                }
                // -------------------------------------------
                // BALANCE CHECKS AND UPDATES
                // -------------------------------------------
                // 12. Combine `from_` with the balance slot seed and store in memory.
                //     This is how we locate from's balance storage slot.
                mstore(0x0c, or(from_, _BALANCE_SLOT_SEED))
                // 13. keccak256 over [0x0c..0x2b] (32 bytes) -> fromBalanceSlot.
                let fromBalanceSlot := keccak256(0x0c, 0x20)
                // 14. Load from's balance from storage.
                let fromBalance := sload(fromBalanceSlot)
                // 15. Revert if fromBalance < amount.
                if gt(amount, fromBalance) {
                    mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                    revert(0x1c, 0x04)
                }
                // 16. Subtract amount from from's balance and store it.
                sstore(fromBalanceSlot, sub(fromBalance, amount))
                // -------------------------------------------
                // CREDIT THE RECIPIENT
                // -------------------------------------------
                // 17. Now compute to's balance slot in the same manner.
                mstore(0x00, to)
                let toBalanceSlot := keccak256(0x0c, 0x20)
                // 18. Add amount to to's balance and store it.
                //     Overflow is not possible here since the total supply
                //     cannot exceed the maximum uint256 value, so no additional checks needed.
                sstore(toBalanceSlot, add(sload(toBalanceSlot), amount))
                // -------------------------------------------
                // EMIT Transfer EVENT
                // -------------------------------------------
                // 19. Store `amount` in memory, then emit the Transfer event:
                //     log3(top_of_data, size, signature, from, to).
                mstore(0x20, amount)
                log3(0x20, 0x20, _TRANSFER_EVENT_SIGNATURE, shr(96, from_), shr(96, mload(0x0c)))
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                // -------------------------------------------
                // SHIFTING AND PREPARATION
                // -------------------------------------------
                let from_ := shl(96, from)
                // -------------------------------------------
                // ALLOWANCE CHECKS
                // -------------------------------------------
                // 1. We always do an allowance check in this branch.
                mstore(0x20, caller())
                mstore(0x0c, or(from_, _ALLOWANCE_SLOT_SEED))
                // 2. allowanceSlot is the keccak256 of [0x0c..0x3f].
                let allowanceSlot := keccak256(0x0c, 0x34)
                // 3. Load the stored allowance.
                let allowance_ := sload(allowanceSlot)
                // 4. If allowance_ != type(uint256).max, do a normal allowance check.
                if not(allowance_) {
                    // Revert if the amount to be transferred exceeds the allowance.
                    if gt(amount, allowance_) {
                        mstore(0x00, 0x13be252b) // `InsufficientAllowance()`.
                        revert(0x1c, 0x04)
                    }
                    // Subtract and store the updated allowance.
                    sstore(allowanceSlot, sub(allowance_, amount))
                }
                // -------------------------------------------
                // BALANCE CHECKS AND UPDATES
                // -------------------------------------------
                // 5. Now handle the balances exactly like in transfer.
                // Compute the balance slot and load its value.
                mstore(0x0c, or(from_, _BALANCE_SLOT_SEED))
                let fromBalanceSlot := keccak256(0x0c, 0x20)
                let fromBalance := sload(fromBalanceSlot)
                // Revert if insufficient balance.
                if gt(amount, fromBalance) {
                    mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                    revert(0x1c, 0x04)
                }
                // Subtract and store the updated balance.
                sstore(fromBalanceSlot, sub(fromBalance, amount))
                // -------------------------------------------
                // CREDIT THE RECIPIENT
                // -------------------------------------------
                // Compute the balance slot of `to`.
                mstore(0x00, to)
                let toBalanceSlot := keccak256(0x0c, 0x20)
                // Add and store the updated balance of `to`.
                // Will not overflow because the sum of all user balances
                // cannot exceed the maximum uint256 value.
                sstore(toBalanceSlot, add(sload(toBalanceSlot), amount))
                // -------------------------------------------
                // EMIT Transfer EVENT
                // -------------------------------------------
                // Emit the {Transfer} event.
                mstore(0x20, amount)
                log3(0x20, 0x20, _TRANSFER_EVENT_SIGNATURE, shr(96, from_), shr(96, mload(0x0c)))
            }
        }
        // -------------------------------------------
        // 3. Call a hook that can be overridden to run code after every transfer.
        // -------------------------------------------
        _afterTokenTransfer(from, to, amount);
        // -------------------------------------------
        // 4. Return true to signal successful transfer.
        // -------------------------------------------
        return true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EIP-2612                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev For more performance, override to return the constant value
    /// of `keccak256(bytes(name()))` if `name()` will never change.
    function _constantNameHash() internal view virtual returns (bytes32 result) {}

    /// @dev If you need a different value, override this function.
    function _versionHash() internal view virtual returns (bytes32 result) {
        result = _DEFAULT_VERSION_HASH;
    }

    /// @dev For inheriting contracts to increment the nonce.
    function _incrementNonce(address owner) internal virtual {
        /// @solidity memory-safe-assembly
        assembly {
            // ----------------------------------------------------------------------
            // 1. Write _NONCES_SLOT_SEED into memory at offset 0x0c.
            //
            //    This instruction writes 32 bytes of data, starting at [0x0c..0x2b].
            //    Conceptually:
            //       memory[0x0c..0x2b] = _NONCES_SLOT_SEED
            // ----------------------------------------------------------------------
            mstore(0x0c, _NONCES_SLOT_SEED)
            // ----------------------------------------------------------------------
            // 2. Write `owner` into memory at offset 0x00.
            //
            //    This also writes 32 bytes (the address `owner` left-padded with zeros),
            //    covering [0x00..0x1f].
            //
            //    There is an overlap region [0x0c..0x1f] where the bytes written here
            //    partially overwrite some of the bytes from step 1. This is a known
            //    trick to create a deterministic layout that combines `owner` and
            //    `_NONCES_SLOT_SEED` into a single 32-byte chunk for hashing.
            // ----------------------------------------------------------------------
            mstore(0x00, owner)
            // ----------------------------------------------------------------------
            // 3. Compute the keccak256 hash over 32 bytes at [0x0c..0x2b].
            //
            //    The memory region from 0x0c to 0x0c + 0x20 (i.e. 0x2b) now contains
            //    a specific mix of `owner` and `_NONCES_SLOT_SEED` data.
            //    This forms a unique key for the owner's nonce storage slot.
            //
            //    The result is stored in `nonceSlot`, which is the storage slot
            //    where we keep the `owner`'s nonce.
            // ----------------------------------------------------------------------
            let nonceSlot := keccak256(0x0c, 0x20)
            // ----------------------------------------------------------------------
            // 4. Increment the nonce stored at `nonceSlot` by 1.
            //
            //    sload(nonceSlot) loads the old nonce.
            //    add(1, sload(nonceSlot)) increments it by 1.
            //    sstore(nonceSlot, ...) writes it back into storage.
            // ----------------------------------------------------------------------
            sstore(nonceSlot, add(1, sload(nonceSlot)))
        }
    }

    /// @dev Returns the current nonce for `owner`.
    /// This value is used to compute the signature for EIP-2612 permit.
    function nonces(address owner) public view virtual returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            // ---------------------------------------------------------
            // 1. Write the _NONCES_SLOT_SEED into memory at offset 0x0c.
            //
            //    This places 32 bytes (the slot seed) into memory
            //    starting from address 0x0c to 0x2b.
            // ---------------------------------------------------------
            mstore(0x0c, _NONCES_SLOT_SEED)
            // ---------------------------------------------------------
            // 2. Write the 'owner' address into memory at offset 0x00.
            //
            //    mstore will left-pad the address to 32 bytes.
            //    So memory [0x00..0x1f] now holds (12 bytes of zero + 20 bytes of address).
            // ---------------------------------------------------------
            mstore(0x00, owner)
            // ---------------------------------------------------------
            // 3. Compute the keccak256 hash of the 32 bytes at [0x0c..0x2b].
            //
            //    This effectively "mixes" (owner, _NONCES_SLOT_SEED)
            //    to produce a unique storage slot, which we then load
            //    using sload.
            // ---------------------------------------------------------
            result := sload(keccak256(0x0c, 0x20))
        }
    }

    /// @dev Sets `value` as the allowance of `spender` over the tokens of `owner`,
    /// authorized by a signed approval by `owner`.
    ///
    /// Emits a {Approval} event.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        // ------------------------------------------------------------------------------
        // 1. If `_givePermit2InfiniteAllowance()` is true, it implies that if `spender`
        //    is `_PERMIT2`, the allowance must remain infinite (uint256.max).
        //    If the user tries to set an allowance != type(uint256).max for `_PERMIT2`,
        //    we revert with `Permit2AllowanceIsFixedAtInfinity()`.
        // ------------------------------------------------------------------------------
        if (_givePermit2InfiniteAllowance()) {
            /// @solidity memory-safe-assembly
            assembly {
                // If `spender == _PERMIT2 && value != type(uint256).max`.
                //
                // The condition:
                //   if iszero(or(xor(shr(96, shl(96, spender)), _PERMIT2), iszero(not(value)))) {
                //
                // breaks down as follows:
                //
                //   1) shl(96, spender)  => shift spender left 96 bits
                //   2) shr(96, ...)      => shift right 96 bits
                //                         => effectively a no-op for a clean 20-byte address,
                //                            but ensures top/bottom bits are zeroed
                //   3) xor( ..., _PERMIT2 )
                //      => 0 if the 20-byte part of `spender` is exactly `_PERMIT2`
                //   4) not(value)        => bitwise NOT of `value`.
                //      => 0 if `value == type(uint256).max`,
                //         nonzero otherwise
                //   5) iszero( not(value) )
                //      => true (1) if `value == type(uint256).max`; false (0) otherwise
                //   6) or( <X>, <Y> )
                //      => true if either <X> or <Y> is nonzero
                //   7) iszero( or(...) )
                //      => condition is `true` if BOTH <X> and <Y> are zero
                //
                // So overall, "if iszero(or(xor(...), iszero(not(value)))))" means:
                //   => if (xor(...) == 0) AND (iszero(not(value)) == 0)
                //   => if (spender is exactly _PERMIT2) AND (value != type(uint256).max)
                //
                // => revert with "Permit2AllowanceIsFixedAtInfinity()"
                if iszero(or(xor(shr(96, shl(96, spender)), _PERMIT2), iszero(not(value)))) {
                    // This reverts if spender == _PERMIT2 && value != type(uint256).max
                    mstore(0x00, 0x3f68539a) // `Permit2AllowanceIsFixedAtInfinity()`.
                    revert(0x1c, 0x04)
                }
            }
        }
        // ------------------------------------------------------------------------------
        // 2. Prepare the `nameHash`. If _constantNameHash() returns 0, we compute
        //    keccak256(bytes(name())) on the fly. This is used in the domain separator.
        // ------------------------------------------------------------------------------
        bytes32 nameHash = _constantNameHash();
        //  We simply calculate it on-the-fly to allow for cases where the `name` may change.
        if (nameHash == bytes32(0)) nameHash = keccak256(bytes(name()));
        // 3. Prepare the `versionHash` if needed.
        bytes32 versionHash = _versionHash();
        /// @solidity memory-safe-assembly
        assembly {
            // ------------------------------------------------------------------------------
            // 4. Check `deadline`. If current block.timestamp > deadline, revert.
            // ------------------------------------------------------------------------------
            if gt(timestamp(), deadline) {
                mstore(0x00, 0x1a15a3cc) // `PermitExpired()`.
                revert(0x1c, 0x04)
            }
            // ------------------------------------------------------------------------------
            // 5. Grab the free memory pointer so we can reuse it for domain + struct hashes.
            // ------------------------------------------------------------------------------
            let m := mload(0x40)
            // ------------------------------------------------------------------------------
            // 6. "Clean" the upper 96 bits of `owner` and `spender`.
            //    This ensures addresses are truncated / zero-padded properly.
            // ------------------------------------------------------------------------------
            owner := shr(96, shl(96, owner))
            spender := shr(96, shl(96, spender))
            // ------------------------------------------------------------------------------
            // 7. Compute the nonce slot for `owner`:
            //    We do so by storing _NONCES_SLOT_SEED_WITH_SIGNATURE_PREFIX (1901 + seed)
            //    then hashing. We load the nonce from that slot.
            // ------------------------------------------------------------------------------

            mstore(0x0e, _NONCES_SLOT_SEED_WITH_SIGNATURE_PREFIX)
            mstore(0x00, owner)
            let nonceSlot := keccak256(0x0c, 0x20)
            let nonceValue := sload(nonceSlot)
            // ------------------------------------------------------------------------------
            // 8. Prepare the domain separator in memory:
            //      domainSeparator = keccak256(
            //         abi.encode(
            //           _DOMAIN_TYPEHASH,
            //           nameHash,
            //           versionHash,
            //           chainid(),
            //           address(this)
            //         )
            //      )
            // ------------------------------------------------------------------------------
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), nameHash)
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), address())
            mstore(0x2e, keccak256(m, 0xa0))
            // ------------------------------------------------------------------------------
            // 9. Prepare the struct hash in memory:
            //    structHash = keccak256(
            //       abi.encode(
            //         _PERMIT_TYPEHASH,
            //         owner,
            //         spender,
            //         value,
            //         nonceValue,
            //         deadline
            //       )
            //    )
            // ------------------------------------------------------------------------------
            mstore(m, _PERMIT_TYPEHASH)
            mstore(add(m, 0x20), owner)
            mstore(add(m, 0x40), spender)
            mstore(add(m, 0x60), value)
            mstore(add(m, 0x80), nonceValue)
            mstore(add(m, 0xa0), deadline)
            mstore(0x4e, keccak256(m, 0xc0))
            // ------------------------------------------------------------------------------
            // 10. Prepare ecrecover input:
            //     keccak256("\x19\x01", domainSeparator, structHash)
            // ------------------------------------------------------------------------------
            mstore(0x00, keccak256(0x2c, 0x42))
            //  Next 3 stores:
            //    [0x20] = v,
            //    [0x40] = r,
            //    [0x60] = s
            mstore(0x20, and(0xff, v))
            mstore(0x40, r)
            mstore(0x60, s)
            // ------------------------------------------------------------------------------
            // 11. staticcall(ecrecover):
            //     - If the call fails or returns zero bytes, ecrecover fails => we revert.
            //     - If successful, we get a 32-byte returned address at [0x20..0x3f].
            // ------------------------------------------------------------------------------
            let t := staticcall(gas(), 1, 0x00, 0x80, 0x20, 0x20)
            // If the ecrecover fails, the returndatasize will be 0x00,
            // `owner` will be checked if it equals the hash at 0x00,
            // which evaluates to false (i.e. 0), and we will revert.
            // If the ecrecover succeeds, the returndatasize will be 0x20,
            // `owner` will be compared against the returned address at 0x20.
            if iszero(eq(mload(returndatasize()), owner)) {
                mstore(0x00, 0xddafbaef) // `InvalidPermit()`.
                revert(0x1c, 0x04)
            }
            // ------------------------------------------------------------------------------
            // 13. Increase the nonce by 1 if ecrecover succeeded (t == 1).
            //     sstore(nonceSlot, nonceValue + 1).
            // ------------------------------------------------------------------------------
            sstore(nonceSlot, add(nonceValue, t)) // `t` is 1 if ecrecover succeeds.
            // ------------------------------------------------------------------------------
            // 14. Finally, set the allowance: allowance[owner][spender] = value.
            // ------------------------------------------------------------------------------
            // The memory at [0x20] is still occupant by r previously, so we:
            //   mstore(0x40, or(shl(160, _ALLOWANCE_SLOT_SEED), spender))
            // and then compute keccak256([0x2c..0x5f]) = 52 bytes => slot
            mstore(0x40, or(shl(160, _ALLOWANCE_SLOT_SEED), spender))
            sstore(keccak256(0x2c, 0x34), value)
            // ------------------------------------------------------------------------------
            // 15. Emit the Approval event with {value}, {owner}, {spender}.
            // ------------------------------------------------------------------------------
            log3(add(m, 0x60), 0x20, _APPROVAL_EVENT_SIGNATURE, owner, spender)
            // ------------------------------------------------------------------------------
            // 16. Restore the free memory pointer and zero out the scratch space.
            // ------------------------------------------------------------------------------
            mstore(0x40, m) // Restore the free memory pointer.
            mstore(0x60, 0) // Restore the zero pointer.
        }
    }

    /// @dev Returns the EIP-712 domain separator for the EIP-2612 permit.
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32 result) {
        bytes32 nameHash = _constantNameHash();
        //  We simply calculate it on-the-fly to allow for cases where the `name` may change.
        if (nameHash == bytes32(0)) nameHash = keccak256(bytes(name()));
        bytes32 versionHash = _versionHash();
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Grab the free memory pointer.
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), nameHash)
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), address())
            result := keccak256(m, 0xa0)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL MINT FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mints `amount` tokens to `to`, increasing the total supply.
    ///
    /// Emits a {Transfer} event.
    function _mint(address to, uint256 amount) internal virtual {
        // Hook that can be overridden to run code before any token transfer.
        // Common use-cases include fee logic, blocklisting, etc.
        _beforeTokenTransfer(address(0), to, amount);
        /// @solidity memory-safe-assembly
        assembly {
            // -----------------------------------------------------
            // 1. Load the current total supply from its dedicated slot.
            //    The slot index is at compile-time constant _TOTAL_SUPPLY_SLOT.
            // -----------------------------------------------------
            let totalSupplyBefore := sload(_TOTAL_SUPPLY_SLOT)
            // -----------------------------------------------------
            // 2. Calculate the new total supply by adding `amount`.
            // -----------------------------------------------------
            let totalSupplyAfter := add(totalSupplyBefore, amount)
            // -----------------------------------------------------
            // 3. Check for overflow. If totalSupplyAfter < totalSupplyBefore,
            //    then we've wrapped around (overflowed).
            // -----------------------------------------------------
            if lt(totalSupplyAfter, totalSupplyBefore) {
                mstore(0x00, 0xe5cfe957) // `TotalSupplyOverflow()`.
                revert(0x1c, 0x04)
            }
            // -----------------------------------------------------
            // 4. Store the new total supply in the _TOTAL_SUPPLY_SLOT.
            // -----------------------------------------------------
            sstore(_TOTAL_SUPPLY_SLOT, totalSupplyAfter)
            // -----------------------------------------------------
            // 5. Compute the storage slot for `to`'s balance.
            //    We do so by writing _BALANCE_SLOT_SEED at memory offset 0x0c
            //    and `to` at memory offset 0x00, then hashing the 32 bytes
            //    starting at 0x0c.
            //    That is the pattern used throughout this contract to map
            //    (address => balance).
            // -----------------------------------------------------
            mstore(0x0c, _BALANCE_SLOT_SEED)
            mstore(0x00, to)
            let toBalanceSlot := keccak256(0x0c, 0x20)
            // -----------------------------------------------------
            // 6. sload(toBalanceSlot) loads `to`'s current balance.
            //    We then add `amount` to it, and sstore(...) writes
            //    the updated balance back to storage.
            // -----------------------------------------------------
            sstore(toBalanceSlot, add(sload(toBalanceSlot), amount))
            // -----------------------------------------------------
            // 7. Emit the Transfer event:
            //    - We store `amount` in memory at offset 0x20
            //    - We call log3(...) to emit the event with 3 topics:
            //       * event signature (Transfer)
            //       * the "from" (which is address(0) for mint)
            //       * the "to"   (the mintee, `to`)
            // -----------------------------------------------------
            mstore(0x20, amount)
            log3(0x20, 0x20, _TRANSFER_EVENT_SIGNATURE, 0, shr(96, mload(0x0c)))
        }
        // Hook that can be overridden to run code after any token transfer.
        _afterTokenTransfer(address(0), to, amount);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL BURN FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Burns `amount` tokens from `from`, reducing the total supply.
    ///
    /// Emits a {Transfer} event.
    function _burn(address from, uint256 amount) internal virtual {
        // ----------------------------------------------------------------
        // 1. Hook called before token transfer (from -> address(0))
        //    Derived contracts can override to handle custom logic like fees.
        // ----------------------------------------------------------------
        _beforeTokenTransfer(from, address(0), amount);
        /// @solidity memory-safe-assembly
        assembly {
            // ----------------------------------------------------------------
            // 2. We need to find and load the balance of `from`.
            //    This uses the same method as `transfer` and `_mint`:
            //    - Write _BALANCE_SLOT_SEED at memory offset 0x0c
            //    - Write `from` at memory offset 0x00
            //    - Then hash the 32 bytes at [0x0c..0x2b].
            //    The result is the storage slot for `from`'s balance.
            // ----------------------------------------------------------------
            mstore(0x0c, _BALANCE_SLOT_SEED) // step 1: store seed at 0x0c..0x2b
            mstore(0x00, from) // step 2: store `from` at 0x00..0x1f
            let fromBalanceSlot := keccak256(0x0c, 0x20) // step 3: hash => storage slot
            let fromBalance := sload(fromBalanceSlot) // step 4: load the current balance
            // ----------------------------------------------------------------
            // 3. Revert if `from` has fewer tokens than `amount`.
            // ----------------------------------------------------------------
            if gt(amount, fromBalance) {
                mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                revert(0x1c, 0x04)
            }
            // ----------------------------------------------------------------
            // 4. Subtract `amount` from `from`'s balance and write it back.
            // ----------------------------------------------------------------
            sstore(fromBalanceSlot, sub(fromBalance, amount))
            // ----------------------------------------------------------------
            // 5. Update the total supply in the _TOTAL_SUPPLY_SLOT.
            //    Load the current total supply, subtract `amount`, and store it.
            // ----------------------------------------------------------------
            sstore(_TOTAL_SUPPLY_SLOT, sub(sload(_TOTAL_SUPPLY_SLOT), amount))
            // ----------------------------------------------------------------
            // 6. Emit the Transfer event indicating tokens are burned:
            //    - We store `amount` at offset 0x00.
            //    - Use log3(...), with:
            //       topic #0 => _TRANSFER_EVENT_SIGNATURE
            //       topic #1 => 'from'
            //       topic #2 => address(0) (in a burned scenario)
            // ----------------------------------------------------------------
            mstore(0x00, amount)
            log3(0x00, 0x20, _TRANSFER_EVENT_SIGNATURE, shr(96, shl(96, from)), 0)
        }
        // ----------------------------------------------------------------
        // 7. Hook called after token transfer (from -> address(0)).
        //    Derived contracts can override to handle further logic.
        // ----------------------------------------------------------------
        _afterTokenTransfer(from, address(0), amount);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                INTERNAL TRANSFER FUNCTIONS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Moves `amount` of tokens from `from` to `to`.
    function _transfer(address from, address to, uint256 amount) internal virtual {
        // ----------------------------------------------------------------
        // 1. Call the hook that can be overridden by inheriting contracts
        //    to do things like fee logic, blocklisting, etc. before transfer.
        // ----------------------------------------------------------------
        _beforeTokenTransfer(from, to, amount);
        /// @solidity memory-safe-assembly
        assembly {
            // ----------------------------------------------------------------
            // 2. Shift `from` address to the high 160 bits of a 256-bit register.
            //    This is a typical Solady optimization that helps combine the
            //    address with the slot seed in a single word.
            // ----------------------------------------------------------------
            let from_ := shl(96, from)
            // ----------------------------------------------------------------
            // 3. Compute the storage slot for `from`'s balance:
            //
            //    a) Write `from_ | _BALANCE_SLOT_SEED` into memory at offset 0x0c.
            //       (or() = bitwise OR; effectively merges them in a single 256-bit word)
            //    b) Then call keccak256 over [0x0c..(0x0c + 0x20)) to derive
            //       the unique storage slot for (from => balance).
            // ----------------------------------------------------------------
            mstore(0x0c, or(from_, _BALANCE_SLOT_SEED))
            let fromBalanceSlot := keccak256(0x0c, 0x20)
            // ----------------------------------------------------------------
            // 4. Load `from`'s balance from storage and check if it’s enough.
            // ----------------------------------------------------------------
            let fromBalance := sload(fromBalanceSlot)
            // Revert if insufficient balance.
            if gt(amount, fromBalance) {
                mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`.
                revert(0x1c, 0x04)
            }
            // ----------------------------------------------------------------
            // 5. Subtract `amount` from `from`'s balance and write the result back.
            // ----------------------------------------------------------------
            sstore(fromBalanceSlot, sub(fromBalance, amount))
            // ----------------------------------------------------------------
            // 6. Compute the storage slot for `to`'s balance:
            //    a) Write `to` at memory offset 0x00
            //    b) Hash [0x0c..0x2b] to get the correct slot for (to => balance).
            //
            //    Note: Because we do not shift `to`, we rely on the existing
            //    memory content at 0x0c (the same _BALANCE_SLOT_SEED we used above).
            // ----------------------------------------------------------------
            mstore(0x00, to)
            let toBalanceSlot := keccak256(0x0c, 0x20)
            // ----------------------------------------------------------------
            // 7. Add `amount` to `to`'s balance and store it back.
            //    Overflow check is skipped for performance because total
            //    balances can't exceed type(uint256).max if totalSupply is valid.
            // ----------------------------------------------------------------
            sstore(toBalanceSlot, add(sload(toBalanceSlot), amount))
            // ----------------------------------------------------------------
            // 8. Emit the {Transfer} event:
            //    a) Place `amount` in memory at offset 0x20.
            //    b) Use log3(...) to set the event signature and two indexed topics:
            //         * topic #1: `from`
            //         * topic #2: `to`
            // ----------------------------------------------------------------
            mstore(0x20, amount)
            log3(0x20, 0x20, _TRANSFER_EVENT_SIGNATURE, shr(96, from_), shr(96, mload(0x0c)))
        }
        _afterTokenTransfer(from, to, amount);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                INTERNAL ALLOWANCE FUNCTIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Updates the allowance of `owner` for `spender` based on spent `amount`.
    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {
        // ----------------------------------------------------------------
        // 1. If _givePermit2InfiniteAllowance() returns true and
        //    spender == _PERMIT2, do nothing (infinite allowance).
        // ----------------------------------------------------------------
        if (_givePermit2InfiniteAllowance()) {
            if (spender == _PERMIT2) return; // Do nothing, as allowance is infinite.
        }
        /// @solidity memory-safe-assembly
        assembly {
            // ----------------------------------------------------------------
            // 2. Compute the storage slot for (owner => spender) allowance.
            //
            //    We do this by:
            //      a) mstore(0x20, spender)
            //      b) mstore(0x0c, _ALLOWANCE_SLOT_SEED)
            //      c) mstore(0x00, owner)
            //    Then keccak256 over [0x0c..(0x0c + 0x34)) = 52 bytes
            //    gives us the slot for allowance[owner][spender].
            // ----------------------------------------------------------------
            mstore(0x20, spender) // memory[0x20..0x3f]   = spender (32 bytes)
            mstore(0x0c, _ALLOWANCE_SLOT_SEED)
            /* memory layout now (for hashing):
            *   [0x00..0x0b] = (some zeros or leftover)
            *   [0x0c..0x1f] = _ALLOWANCE_SLOT_SEED (seed)
            *   [0x20..0x3f] = spender 
            */
            mstore(0x00, owner) // memory[0x00..0x1f] = owner (padded to 32 bytes)
            /* final arrangement for hashing 52 bytes [0x0c..0x3f]:
            *   [0x0c..0x1f] + [0x20..0x3f]
            *   => (owner, _ALLOWANCE_SLOT_SEED, spender)
            */
            let allowanceSlot := keccak256(0x0c, 0x34)
            // ----------------------------------------------------------------
            // 3. Load the current allowance and check if it is max uint256.
            //    If it is the maximum, we skip further checks (unlimited).
            //    Otherwise, verify that `amount` <= allowance_.
            // ----------------------------------------------------------------
            let allowance_ := sload(allowanceSlot)
            // if not(allowance_) is effectively: "if allowance_ != type(uint256).max"
            if not(allowance_) {
                // Revert if the amount to be transferred exceeds the allowance.
                if gt(amount, allowance_) {
                    mstore(0x00, 0x13be252b) // `InsufficientAllowance()`.
                    revert(0x1c, 0x04)
                }
                // Subtract and store the updated allowance.
                sstore(allowanceSlot, sub(allowance_, amount))
            }
        }
    }

    /// @dev Sets `amount` as the allowance of `spender` over the tokens of `owner`.
    ///
    /// Emits a {Approval} event.
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        // ----------------------------------------------------------------
        // 1. If _givePermit2InfiniteAllowance() returns true,
        //    check if (spender == _PERMIT2 && amount != max uint256).
        //    If so, revert with `Permit2AllowanceIsFixedAtInfinity()`.
        // ----------------------------------------------------------------
        if (_givePermit2InfiniteAllowance()) {
            /// @solidity memory-safe-assembly
            assembly {
                // If `spender == _PERMIT2 && amount != type(uint256).max`.
                if iszero(or(xor(shr(96, shl(96, spender)), _PERMIT2), iszero(not(amount)))) {
                    mstore(0x00, 0x3f68539a) // `Permit2AllowanceIsFixedAtInfinity()`.
                    revert(0x1c, 0x04)
                }
            }
        }
        /// @solidity memory-safe-assembly
        assembly {
            // ----------------------------------------------------------------
            // 2. Combine `owner` with the _ALLOWANCE_SLOT_SEED to locate
            //    the correct mapping slot for allowance[owner][spender].
            //
            //    We do a small optimization by shifting owner left by 96 bits,
            //    so the address sits in the top 160 bits of a single word.
            // ----------------------------------------------------------------
            let owner_ := shl(96, owner)
            // ----------------------------------------------------------------
            // 3. Compute the key for the allowance slot:
            //      a) mstore(0x20, spender)
            //      b) mstore(0x0c, or(owner_, _ALLOWANCE_SLOT_SEED))
            //    keccak256 over [0x0c..(0x0c + 0x34)] = 52 bytes
            //    yields the unique storage slot for (owner => spender).
            // ----------------------------------------------------------------
            mstore(0x20, spender)
            mstore(0x0c, or(owner_, _ALLOWANCE_SLOT_SEED))
            // ----------------------------------------------------------------
            // 4. Store `amount` in that allowance slot.
            // ----------------------------------------------------------------
            sstore(keccak256(0x0c, 0x34), amount)
            // ----------------------------------------------------------------
            // 5. Emit the {Approval} event:
            //    - We'll store `amount` in memory[0x00..0x1f],
            //    - Then log3 with:
            //       topic #0 => _APPROVAL_EVENT_SIGNATURE
            //       topic #1 => owner
            //       topic #2 => spender
            // ----------------------------------------------------------------
            mstore(0x00, amount)
            log3(0x00, 0x20, _APPROVAL_EVENT_SIGNATURE, shr(96, owner_), shr(96, mload(0x2c)))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HOOKS TO OVERRIDE                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Hook that is called before any transfer of tokens.
    /// This includes minting and burning.
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual {}

    /// @dev Hook that is called after any transfer of tokens.
    /// This includes minting and burning.
    function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PERMIT2                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether to fix the Permit2 contract's allowance at infinity.
    ///
    /// This value should be kept constant after contract initialization,
    /// or else the actual allowance values may not match with the {Approval} events.
    /// For best performance, return a compile-time constant for zero-cost abstraction.
    function _givePermit2InfiniteAllowance() internal view virtual returns (bool) {
        return false;
    }
}
