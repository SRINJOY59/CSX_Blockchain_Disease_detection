// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EncryptedStorage {
    mapping(address => string) private data;
    mapping(address => string) private keys;

    event DataStored(address indexed user, string encryptedData, string encryptedKey);

    function storeData(string calldata encryptedData, string calldata encryptedKey) external {
        data[msg.sender] = encryptedData;
        keys[msg.sender] = encryptedKey;
        emit DataStored(msg.sender, encryptedData, encryptedKey);
    }

    function retrieveData() external view returns (string memory, string memory) {
        return (data[msg.sender], keys[msg.sender]);
    }
}
