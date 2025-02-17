// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DocumentVerification {
    mapping(uint256 => string) private storedHashes;
    uint256 public hashCount;

    event HashStored(string indexed hash, uint256 index);

    function storeHash(string memory _hash) public {
        require(bytes(_hash).length > 0, "Hash cannot be empty"); // Prevent empty hashes

        storedHashes[hashCount] = _hash;  
        emit HashStored(_hash, hashCount);  
        hashCount++;

        require(keccak256(abi.encodePacked(storedHashes[hashCount - 1])) == keccak256(abi.encodePacked(_hash)), 
                "Storage failed");  // Ensures correct storage
    }


    function getHash(uint256 index) public view returns (string memory) {
        if (hashCount == 0) {
            return ""; // Return an empty string if no hashes exist
        }
        require(index < hashCount, "Index out of bounds");
        return storedHashes[index];
    }

    function verifyHash(string memory _hash) public view returns (bool) {
        bytes32 hashToCheck = keccak256(abi.encodePacked(_hash));

        for (uint256 i = 0; i < hashCount; i++) {
            if (keccak256(abi.encodePacked(storedHashes[i])) == hashToCheck) {
                return true;
            }
        }
        return false;
    }
}
