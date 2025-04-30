// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

contract Hospital {
    // bytes32[] activationKeys;
    mapping(bytes32 => bool) _activationKeysMapping; // stored in storage (in blockchain)
    address owner;

    constructor() {
        owner = msg.sender;
    }

    function addActivationKey(bytes32 activationKey) public {
        require(
            owner == msg.sender,
            "Adding activation key failed. Access denied"
        );
        require(
            !_activationKeysMapping[activationKey],
            "Adding activation key failed. Duplicate key"
        );

        _activationKeysMapping[activationKey] = true;
    }

    function useActivationKey(bytes32 activationKey) public {
        require(
            _activationKeysMapping[activationKey],
            "Using activation key faield. Invalid key"
        );

        delete _activationKeysMapping[activationKey];
    }
}
