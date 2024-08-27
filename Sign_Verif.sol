// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

using ECDSA for bytes32;

contract Sign_Verif {
    struct EIP712Domain {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
    }

    // define what the message hash struct looks like.
    struct Message {
        uint16 version;
        bytes32 schema;
        address receipient;
        uint64 time;
        uint64 expirationTime;
        bool revocable;
        bytes32 refUID;
        bytes data;
        bytes32 salt;
    }

    // The hash of the EIP721 domain struct
    bytes32 constant EIP712DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 public constant MESSAGE_TYPEHASH =
        keccak256(
            "Message(uint16 version,bytes32 schema,address receipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
        );

    // Define what the "domain" struct looks like.
    EIP712Domain eip_712_domain_separator_struct =
        EIP712Domain({
            name: "EAS Attestation", // this can be anything
            version: "0.26", // this can be anything
            chainId: 11155111, // ideally the chainId
            verifyingContract: address(0xC2679fBD37d54388Ce493F1DB75320D236e1815e) // ideally, set this as "this", but can be any contract to verify signatures
        });

    // Now the format of the signatures is known, define who is going to verify the signatures.
    bytes32 public immutable i_domain_separator =
        keccak256(
            abi.encode(
                EIP712DOMAIN_TYPEHASH,
                keccak256(bytes(eip_712_domain_separator_struct.name)),
                keccak256(bytes(eip_712_domain_separator_struct.version)),
                eip_712_domain_separator_struct.chainId,
                eip_712_domain_separator_struct.verifyingContract
            )
        );

    function getSignerEIP712(
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public view returns (address) {
        // Arguments when calculating hash to validate
        // 1: byte(0x19) - the initial 0x19 byte
        // 2: byte(1) - the version byte
        // 3: hashstruct of domain separator (includes the typehash of the domain struct)
        // 4: hashstruct of message (includes the typehash of the message struct)

        bytes1 prefix = bytes1(0x19);
        bytes1 eip712Version = bytes1(0x01); // EIP-712 is version 1 of EIP-191
        bytes32 hashStructOfDomainSeparator = i_domain_separator;

        bytes32 hashedMessage =
            keccak256(
                abi.encode(
                    MESSAGE_TYPEHASH,
                    Message({
                        version: 2,
                        schema: 0x1c12bac4f230477c87449a101f5f9d6ca1c492866355c0a5e27026753e5ebf40,
                        receipient: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045,
                        time: 1724435715,
                        expirationTime: 0,
                        refUID: 0x0000000000000000000000000000000000000000000000000000000000000000,
                        revocable: true,
                        data: abi.encodePacked(bytes32(0x67617574616d0000000000000000000000000000000000000000000000000000)),
                        salt: 0x8af354b397009a1070c1d958e1a3ce0ab6246bdc21ff3f862a42994c6fc2c1ba
                    })
                )
            );

        // And finally, combine them all
        bytes32 digest = keccak256(
            abi.encodePacked(
                prefix,
                eip712Version,
                hashStructOfDomainSeparator,
                hashedMessage
            )
        );
        return ecrecover(digest, _v, _r, _s);
    }

    function verifySigner712(
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        address signer
    ) public view returns (bool) {
        address actualSigner = getSignerEIP712(_v, _r, _s);

        require(signer == actualSigner);
        return true;
    }
}
