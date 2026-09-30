// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/**
 * @title PQHavenRegistry
 * @notice Değiştirilemez Post-Kuantum CBOM ve Hazırlık Kütüğü
 */
contract PQHavenRegistry {
    struct AssessmentRecord {
        bytes32 cbomMerkleRoot;
        uint16 pqriScore;       // 0 - 10000 (100.00%)
        uint8 statusGrade;      // 0: CRITICAL, 1: HIGH, 2: TRANSITIONAL, 3: READY
        uint64 timestamp;
        string auditorDid;
    }

    address public immutable owner;
    mapping(bytes32 => AssessmentRecord) public entityAssessments;

    event AssessmentRegistered(
        bytes32 indexed entityId,
        bytes32 cbomMerkleRoot,
        uint16 pqriScore,
        uint8 statusGrade
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "PQHaven: Unauthorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerAssessment(
        bytes32 entityId,
        bytes32 cbomMerkleRoot,
        uint16 pqriScore,
        uint8 statusGrade,
        string calldata auditorDid
    ) external onlyOwner {
        entityAssessments[entityId] = AssessmentRecord({
            cbomMerkleRoot: cbomMerkleRoot,
            pqriScore: pqriScore,
            statusGrade: statusGrade,
            timestamp: uint64(block.timestamp),
            auditorDid: auditorDid
        });

        emit AssessmentRegistered(entityId, cbomMerkleRoot, pqriScore, statusGrade);
    }
}
