// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Sign_Verif {
    using ECDSA for bytes32;

    struct Attest {
        uint16 version;
        bytes32 schema;
        address recipient;
        uint64 time;
        uint64 expirationTime;
        bool revocable;
        bytes32 refUID;
        bytes data;
        bytes32 salt;
    }

    // EIP712 Domain Hash constant (pre-calculated)
    bytes32 public constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    // Message Type Hash constant
    bytes32 public constant MESSAGE_TYPEHASH =
        keccak256(
            "Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
        );

    // Pre-calculated Domain Separator
    bytes32 public immutable i_domain_separator;

    // Hardcoded constructor values
    constructor() {
        i_domain_separator = keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes("EAS Attestation")),
                keccak256(bytes("0.26")),
                uint256(11155111), // Sepolia Testnet Chain ID
                address(0xC2679fBD37d54388Ce493F1DB75320D236e1815e) // Verifying contract
            )
        );
    }

    // Hardcoded message struct based on input JSON
    function getHardcodedMessage() public pure returns (Attest memory) {
        return Attest({
            version: 2,
            schema: 0x1c12bac4f230477c87449a101f5f9d6ca1c492866355c0a5e27026753e5ebf40,
            recipient: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045,
            time: 1724435715,
            expirationTime: 0,
            revocable: true,
            refUID: 0x0000000000000000000000000000000000000000000000000000000000000000,
            data: hex"67617574616d0000000000000000000000000000000000000000000000000000", // "gautam" in hex with padding
            salt: 0x8af354b397009a1070c1d958e1a3ce0ab6246bdc21ff3f862a42994c6fc2c1ba
        });
    }

    // Internal function to hash the message
    function _hashMessage(Attest memory message) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                MESSAGE_TYPEHASH,
                message.version,
                message.schema,
                message.recipient,
                message.time,
                message.expirationTime,
                message.revocable,
                message.refUID,
                keccak256(message.data), // Hash the data field
                message.salt
            )
        );
    }

    // Get signer from hardcoded signature parts
    function getSignerEIP712() public view returns (address) {
        // Hardcoded message
        Attest memory message = getHardcodedMessage();

        // Hash the message as per EIP-712
        bytes32 messageHash = _hashMessage(message);

        // EIP-712 digest
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", // EIP-191 version byte
                i_domain_separator,
                messageHash
            )
        );

        // Hardcoded signature values
        bytes32 r = 0x5f19cd73e4fb54a8d014150f02068f941fffde1a7382d94265725aa7a8c30861;
        bytes32 s = 0x031ccb397e2e49c76a4e1f070c4c8ed15e59dad4857429c9bd1e8f9a9b0a0846;
        uint8 v = 27;

        // Recover the signer
        return ECDSA.recover(digest, v, r, s);
    }

    // Verify if the recovered signer is the expected one
    function verifySigner712() public view returns (bool) {
        address recoveredSigner = getSignerEIP712();
        address expectedSigner = 0xB1DF9fd903EDcb315eA04ff0B60E53f2a766080e; // Hardcoded signer

        require(recoveredSigner == expectedSigner, "Invalid signature");
        return true;
    }
}
