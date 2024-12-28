// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Simple single owner authorization mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/auth/Ownable.sol)
///
/// @dev Note:
/// This implementation does NOT auto-initialize the owner to `msg.sender`.
/// You MUST call the `_initializeOwner` in the constructor / initializer.
///
/// While the ownable portion follows
/// [EIP-173](https://eips.ethereum.org/EIPS/eip-173) for compatibility,
/// the nomenclature for the 2-step ownership handover may be unique to this codebase.
abstract contract Ownable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The caller is not authorized to call the function.
    error Unauthorized();

    /// @dev The `newOwner` cannot be the zero address.
    error NewOwnerIsZeroAddress();

    /// @dev The `pendingOwner` does not have a valid handover request.
    error NoHandoverRequest();

    /// @dev Cannot double-initialize.
    error AlreadyInitialized();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ownership is transferred from `oldOwner` to `newOwner`.
    /// This event is intentionally kept the same as OpenZeppelin's Ownable to be
    /// compatible with indexers and [EIP-173](https://eips.ethereum.org/EIPS/eip-173),
    /// despite it not being as lightweight as a single argument event.
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    /// @dev An ownership handover to `pendingOwner` has been requested.
    event OwnershipHandoverRequested(address indexed pendingOwner);

    /// @dev The ownership handover to `pendingOwner` has been canceled.
    event OwnershipHandoverCanceled(address indexed pendingOwner);

    /// @dev `keccak256(bytes("OwnershipTransferred(address,address)"))`.
    uint256 private constant _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE =
        0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0;

    /// @dev `keccak256(bytes("OwnershipHandoverRequested(address)"))`.
    uint256 private constant _OWNERSHIP_HANDOVER_REQUESTED_EVENT_SIGNATURE =
        0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d;

    /// @dev `keccak256(bytes("OwnershipHandoverCanceled(address)"))`.
    uint256 private constant _OWNERSHIP_HANDOVER_CANCELED_EVENT_SIGNATURE =
        0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The owner slot is given by:
    /// `bytes32(~uint256(uint32(bytes4(keccak256("_OWNER_SLOT_NOT")))))`.
    /// It is intentionally chosen to be a high value
    /// to avoid collision with lower slots.
    /// The choice of manual storage layout is to enable compatibility
    /// with both regular and upgradeable contracts.
    bytes32 internal constant _OWNER_SLOT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;

    /// The ownership handover slot of `newOwner` is given by:
    /// ```
    ///     mstore(0x00, or(shl(96, user), _HANDOVER_SLOT_SEED))
    ///     let handoverSlot := keccak256(0x00, 0x20)
    /// ```
    /// It stores the expiry timestamp of the two-step ownership handover.
    uint256 private constant _HANDOVER_SLOT_SEED = 0x389a75e1;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Override to return true to make `_initializeOwner` prevent double-initialization.
    function _guardInitializeOwner() internal pure virtual returns (bool guard) {}

    /// @dev Initializes the owner directly without authorization guard.
    /// This function must be called upon initialization,
    /// regardless of whether the contract is upgradeable or not.
    /// This is to enable generalization to both regular and upgradeable contracts,
    /// and to save gas in case the initial owner is not the caller.
    /// For performance reasons, this function will not check if there
    /// is an existing owner.
    function _initializeOwner(address newOwner) internal virtual {
        // -----------------------------------------------------
        // 1. Check if the guard is enabled.
        //    For non-upgradeable contracts, _guardInitializeOwner() ensures ownership cannot be reset after the first initialization.
        //    For upgradeable contracts, reinitialization of the owner state if _guardInitializeOwner() is overridden to permit it.
        // -----------------------------------------------------
        if (_guardInitializeOwner()) {
            /// @solidity memory-safe-assembly
            assembly {
                // -----------------------------------------------------
                // 2. Load the owner slot into memory.
                //    `_OWNER_SLOT` is a constant storage slot where
                //    the owner's address is stored.
                // -----------------------------------------------------
                let ownerSlot := _OWNER_SLOT
                // -----------------------------------------------------
                // 3. Check if the owner slot already has a value.
                //    If the slot is non-zero, it means the owner has
                //    already been initialized. In that case, revert
                //    with the error `AlreadyInitialized()`.
                // -----------------------------------------------------
                if sload(ownerSlot) {
                    mstore(0x00, 0x0dc149f0) // `AlreadyInitialized()`.
                    revert(0x1c, 0x04)
                }
                // -----------------------------------------------------
                // 4. Clean the upper 96 bits of `newOwner`.
                //    This ensures the input address is properly sanitized
                //    and avoids any accidental use of high bits, which
                //    could lead to incorrect storage values.
                //    Q) But why is this necessary given that Solidity enforces the address type to be 20 bytes?
                //    A) While Solidity ensures type safety, there could be edge cases where the upper bits are
                //    accidentally set during assembly operations or passed from poorly-written external contracts.
                // -----------------------------------------------------
                newOwner := shr(96, shl(96, newOwner))
                // -----------------------------------------------------
                // 5. Store the sanitized owner address in the slot.
                //    If `newOwner` is `address(0)`, the high 255th bit
                //    is set as a flag to indicate an invalid state.
                // +----------------+--------------------+----------------------------+
                // | Bit Range      | Data              | Description                |
                // +----------------+--------------------+----------------------------+
                // | 0 - 159        | `newOwner`        | Owner address (20 bytes)   |
                // | 160 - 254      | (Unused)          | Unused    |
                // | 255            | `isZeroAddress`   | 1 if `newOwner == 0x0`     |
                // +----------------+--------------------+----------------------------+
                // Q) Why set the high 255th bit to 1 if `newOwner == 0x0`?
                // A) To prevent reinitialization of the owner state when `newOwner == 0x0`.
                // -----------------------------------------------------
                sstore(ownerSlot, or(newOwner, shl(255, iszero(newOwner))))
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, 0, newOwner)
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                // Clean the upper 96 bits.
                newOwner := shr(96, shl(96, newOwner))
                // Store the new value.
                sstore(_OWNER_SLOT, newOwner)
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, 0, newOwner)
            }
        }
    }

    /// @dev Sets the owner directly without authorization guard.
    function _setOwner(address newOwner) internal virtual {
        // check if the guard is enabled
        if (_guardInitializeOwner()) {
            /// @solidity memory-safe-assembly
            assembly {
                // -----------------------------------------------------
                // 1. Load the owner slot into memory.
                //    `_OWNER_SLOT` is a predefined constant representing
                //    the storage slot where the owner's address is stored.
                // -----------------------------------------------------
                let ownerSlot := _OWNER_SLOT
                // -----------------------------------------------------
                // 2. Clean the upper 96 bits of `newOwner`.
                //    Solidity's address type is stored in the lower
                //    160 bits of a 256-bit word. This operation ensures
                //    the upper 96 bits are zeroed out to avoid
                //    potential garbage or unintended data in those bits.
                // -----------------------------------------------------
                newOwner := shr(96, shl(96, newOwner))
                // -----------------------------------------------------
                // 3. Emit the `OwnershipTransferred` event.
                //    The `log3` assembly instruction is used to log an
                //    event with three indexed topics:
                //    - Event signature (`_OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE`)
                //    - Old owner (`sload(ownerSlot)`)
                //    - New owner (`newOwner`)
                // -----------------------------------------------------
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, sload(ownerSlot), newOwner)
                // -----------------------------------------------------
                // 4. Store the new owner in the owner slot.
                //    If `newOwner` is `address(0)` (zero address), the
                //    high bit (255th bit) is set to `1` as a marker.
                //    Otherwise, the owner's address is stored as-is.
                // -----------------------------------------------------
                sstore(ownerSlot, or(newOwner, shl(255, iszero(newOwner))))
            }
        } else {
            /// @solidity memory-safe-assembly
            assembly {
                let ownerSlot := _OWNER_SLOT
                // Clean the upper 96 bits.
                newOwner := shr(96, shl(96, newOwner))
                // Emit the {OwnershipTransferred} event.
                log3(0, 0, _OWNERSHIP_TRANSFERRED_EVENT_SIGNATURE, sload(ownerSlot), newOwner)
                // Store the new value.
                sstore(ownerSlot, newOwner)
            }
        }
    }

    /// @dev Throws if the sender is not the owner.
    function _checkOwner() internal view virtual {
        /// @solidity memory-safe-assembly
        assembly {
            // -----------------------------------------------------
            // Compare the caller's address (`caller()`) with the
            // stored owner's address.
            //    - `caller()` is the address of the current function caller.
            //    - `eq(a, b)` checks if `a` equals `b`.
            //    - `iszero(x)` returns `1` if `x` is `0` and `0` otherwise.
            // If the caller is not the stored owner, revert.
            // -----------------------------------------------------
            if iszero(eq(caller(), sload(_OWNER_SLOT))) {
                mstore(0x00, 0x82b42900) // `Unauthorized()`.
                revert(0x1c, 0x04)
            }
        }
    }

    /// @dev Returns how long a two-step ownership handover is valid for in seconds.
    /// Override to return a different value if needed.
    /// Made internal to conserve bytecode. Wrap it in a public function if needed.
    function _ownershipHandoverValidFor() internal view virtual returns (uint64) {
        return 48 * 3600;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  PUBLIC UPDATE FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Allows the owner to transfer the ownership to `newOwner`.
    function transferOwnership(address newOwner) public payable virtual onlyOwner {
        /// @solidity memory-safe-assembly
        assembly {
            // -----------------------------------------------------
            // Check if `newOwner` is a valid address.
            //    - `shl(96, newOwner)` shifts the lower 160 bits to
            //      the upper part of the word, clearing the high 96 bits.
            //    - after clearing the high 96 bits, checks if the `newOwner` is zero address.
            // -----------------------------------------------------
            if iszero(shl(96, newOwner)) {
                mstore(0x00, 0x7448fbae) // `NewOwnerIsZeroAddress()`.
                revert(0x1c, 0x04)
            }
        }
        _setOwner(newOwner);
    }

    /// @dev Allows the owner to renounce their ownership.
    function renounceOwnership() public payable virtual onlyOwner {
        _setOwner(address(0));
    }

    /// @dev Request a two-step ownership handover to the caller.
    /// The request will automatically expire in 48 hours (172800 seconds) by default.
    function requestOwnershipHandover() public payable virtual {
        unchecked {
            // -----------------------------------------------------
            // 1. Calculate the expiration timestamp for the handover.
            //    - `_ownershipHandoverValidFor()` typically returns
            //      `48 * 3600` (48 hours in seconds).
            //    - Add the current timestamp (`block.timestamp`) to
            //      calculate the expiration time.
            // -----------------------------------------------------
            uint256 expires = block.timestamp + _ownershipHandoverValidFor();
            /// @solidity memory-safe-assembly
            assembly {
                // -----------------------------------------------------
                // 2. Compute the storage slot for the caller's handover and store the expiration timestamp
                //    request expiration using `_HANDOVER_SLOT_SEED`.
                //    - Store `_HANDOVER_SLOT_SEED` at offset `0x0c`.
                //    - Store the caller's address at offset `0x00`.
                //    - `keccak256(0x0c, 0x20)` hashes the (caller's address, _HANDOVER_SLOT_SEED)
                // Memory offsets:   0x00                   0x0c           0x1f 0x20         0x2c
                //                   |----------------------|--------------|----|------------|
                // Write #2 covers:  [0x00 --------------------------------- 0x1f]
                // Write #1 covers:                             [0x0c ----------------- 0x2b]
                // Final memory:
                // - [0x00 .. 0x0b] : Upper 96 bits of the zero-extended address
                // - [0x0c .. 0x1f] : Lower 160 bits of `caller()` (overwriting that part of the seed)
                // - [0x20 .. 0x2b] : Actual `_HANDOVER_SLOT_SEED` (typically the last 12 bytes)
                // - [0x2c .. ... ] : Unchanged
                // -----------------------------------------------------
                mstore(0x0c, _HANDOVER_SLOT_SEED)
                mstore(0x00, caller())
                sstore(keccak256(0x0c, 0x20), expires)
                // Emit the {OwnershipHandoverRequested} event.
                log2(0, 0, _OWNERSHIP_HANDOVER_REQUESTED_EVENT_SIGNATURE, caller())
            }
        }
    }

    /// @dev Cancels the two-step ownership handover to the caller, if any.
    function cancelOwnershipHandover() public payable virtual {
        /// @solidity memory-safe-assembly
        assembly {
            // -----------------------------------------------------
            // 1. Prepare memory for computing the storage slot and store zero:
            //    - `mstore(0x0c, _HANDOVER_SLOT_SEED)` writes the
            //      `_HANDOVER_SLOT_SEED` constant at offset 0x0c.
            //    - `mstore(0x00, caller())` writes the caller's
            //      address at offset 0x00.
            // Memory offsets:   0x00                   0x0c           0x1f 0x20         0x2c
            //                   |----------------------|--------------|----|------------|
            // Write #2 covers:  [0x00 --------------------------------- 0x1f]
            // Write #1 covers:                             [0x0c ----------------- 0x2b]
            // Final memory:
            // - [0x00 .. 0x0b] : Upper 96 bits of the zero-extended address
            // - [0x0c .. 0x1f] : Lower 160 bits of `caller()` (overwriting that part of the seed)
            // - [0x20 .. 0x2b] : Actual `_HANDOVER_SLOT_SEED` (typically the last 12 bytes)
            // - [0x2c .. ... ] : Unchanged
            // -----------------------------------------------------
            mstore(0x0c, _HANDOVER_SLOT_SEED)
            mstore(0x00, caller())
            sstore(keccak256(0x0c, 0x20), 0)
            // Emit the {OwnershipHandoverCanceled} event.
            log2(0, 0, _OWNERSHIP_HANDOVER_CANCELED_EVENT_SIGNATURE, caller())
        }
    }

    /// @dev Allows the owner to complete the two-step ownership handover to `pendingOwner`.
    /// Reverts if there is no existing ownership handover requested by `pendingOwner`.
    function completeOwnershipHandover(address pendingOwner) public payable virtual onlyOwner {
        /// @solidity memory-safe-assembly
        assembly {
            // -----------------------------------------------------
            // 1. Prepare memory for computing the storage slot:
            //    - Store `_HANDOVER_SLOT_SEED` at offset 0x0c.
            //    - Store `pendingOwner` at offset 0x00.
            // Same technique as in `requestOwnershipHandover()`.
            // -----------------------------------------------------
            mstore(0x0c, _HANDOVER_SLOT_SEED)
            mstore(0x00, pendingOwner)
            // -----------------------------------------------------
            // 2. Compute the storage slot for `pendingOwner` using
            //    keccak256(0x0c, 0x20), same pattern as above.
            // -----------------------------------------------------
            let handoverSlot := keccak256(0x0c, 0x20)
            // -----------------------------------------------------
            // 3. Validate that the request exists and hasn't expired:
            //    - `sload(handoverSlot)` loads the expiration timestamp.
            //    - `timestamp()` is the current block.timestamp.
            //    - If `block.timestamp` > expiration, revert with
            //      `NoHandoverRequest()`.
            // -----------------------------------------------------
            if gt(timestamp(), sload(handoverSlot)) {
                mstore(0x00, 0x6f5e8818) // `NoHandoverRequest()`.
                revert(0x1c, 0x04)
            }
            // -----------------------------------------------------
            // 4. Invalidate the slot by setting it to 0.
            //    This completes the request and prevents reusing
            //    the same expiration timestamp again.
            // -----------------------------------------------------
            sstore(handoverSlot, 0)
        }
        _setOwner(pendingOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   PUBLIC READ FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the owner of the contract.
    function owner() public view virtual returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := sload(_OWNER_SLOT)
        }
    }

    /// @dev Returns the expiry timestamp for the two-step ownership handover to `pendingOwner`.
    function ownershipHandoverExpiresAt(address pendingOwner)
        public
        view
        virtual
        returns (uint256 result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // -----------------------------------------------------
            // 1. Prepare memory for computing the storage slot:
            //    - Store `_HANDOVER_SLOT_SEED` at offset 0x0c.
            //    - Store `pendingOwner` at offset 0x00.
            // Same technique as in `requestOwnershipHandover()`.
            // -----------------------------------------------------
            mstore(0x0c, _HANDOVER_SLOT_SEED)
            mstore(0x00, pendingOwner)
            // -----------------------------------------------------
            // 2. Load the handover expiration:
            //    - The slot is keccak256(0x0c, 0x20).
            //    - `sload(...)` returns the current expiration
            //      timestamp for `pendingOwner`’s handover request.
            // -----------------------------------------------------
            result := sload(keccak256(0x0c, 0x20))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         MODIFIERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Marks a function as only callable by the owner.
    modifier onlyOwner() virtual {
        _checkOwner();
        _;
    }
}
