# Solady-Annotated

This is a fork of [Solady](https://github.com/Vectorized/solady) with added annotations.
If you’re not familiar with Solidity assembly but want to understand Solady contracts, this repo is for you.
The detailed comments will guide you through the code, making it easier to understand and helping you develop your own contracts using Solady.

## List of Annotated Contracts

-   [x] [ERC20](https://github.com/adnpark/solady-annotated/blob/main/src/tokens/ERC20.sol)

## To be annotated next

-   ERC721
-   ERC1155
-   Ownable
-   ECDSA
-   MerkleProof
-   SignatureCheckerLib
-   ReentrancyGuard
-   and more...

## How to read annotations

-   To get a general overview of the contract, simply follow the numbered comments.
-   To dive into the detailed magic behind the assembly code, read all the comments from top to bottom.

```solidity
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
```
