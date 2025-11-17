# Comparison of E2E Verifiable Voting Systems

This document provides a detailed comparison between VoteSecure and other prominent end-to-end verifiable (E2E-V) voting systems, including Helios, Belenios, and the Swiss Post system. This comparison addresses questions raised in [FreeAndFair/VoteSecure#2](https://github.com/FreeAndFair/VoteSecure/issues/2).

## Overview

End-to-end verifiable voting systems aim to provide mathematical guarantees that:
1. **Cast-as-intended**: The ballot is encrypted as the voter intended
2. **Recorded-as-cast**: The encrypted ballot on the bulletin board matches what the voter cast
3. **Tallied-as-cast**: All recorded ballots are correctly included in the tally

Different E2E-V systems make different trade-offs in their threat models, privacy guarantees, and verification mechanisms.

## Helios

**Background**: Helios is one of the earliest and most well-known E2E-V systems, designed primarily for low-coercion elections (e.g., student government, organizational elections).

### Similarities with VoteSecure
- Uses ElGamal encryption for ballot privacy
- Provides cast-as-intended, recorded-as-cast, and tallied-as-cast verification
- Uses a public bulletin board for transparency
- Supports individual and universal verifiability

### Key Differences
1. **Tallying Method**: Helios uses homomorphic tallying, which allows votes to be counted without full decryption. VoteSecure (in its first version) uses a mixnet approach, which better supports:
   - Traditional election official workflows (produces individual ballot images)
   - Write-in candidates (which are difficult with homomorphic tallying)
   - Integration with existing tabulation systems

2. **Ballot Verification**: 
   - Helios typically uses a Benaloh challenge, where voters can audit randomly selected ballots before committing to cast
   - VoteSecure's ballot check application can run on a separate, independent device, providing stronger protection against a compromised voting client

3. **Threat Model**:
   - Helios was designed for controlled environments (e.g., university elections)
   - VoteSecure explicitly models advanced persistent threats (APTs) on mobile devices, including malicious applications that may attempt to compromise the voting app

4. **Receipt-freeness**: Neither system provides receipt-freeness in the traditional cryptographic sense. In both systems, a modified client could retain encryption randomness, allowing vote selling.

## Belenios

**Background**: Belenios is an open-source E2E-V system developed as an improvement over Helios, with a strong emphasis on formal verification.

### Similarities with VoteSecure
- Both emphasize formal verification of cryptographic protocols
- Both are open source
- Both provide individual and universal verifiability
- Both acknowledge the receipt-freeness limitation in remote voting scenarios

### Key Differences
1. **Development Methodology**:
   - Belenios uses formal verification focused primarily on the cryptographic protocol layer
   - VoteSecure uses rigorous digital engineering (RDE) methodology with formal refinement from high-level domain models through executable specifications down to implementation, providing traceability across all abstraction levels

2. **Tallying**:
   - Belenios uses homomorphic tallying
   - VoteSecure uses mixnet-based decryption for better workflow compatibility

3. **Threat Model Scope**:
   - VoteSecure's threat model explicitly addresses APTs across all environments, with particular attention to mobile device threats (malicious apps, cross-app vulnerabilities)
   - This makes VoteSecure's threat model more comprehensive for Internet voting from personal devices

4. **Assurance Case**:
   - VoteSecure includes a formal assurance case connecting models, specifications, and implementation, designed to support government certification processes
   - This assurance case approach is intended to facilitate adoption by multiple voting system vendors

## Swiss Post System

**Background**: The Swiss Post e-voting system was used in Switzerland for several years but was discontinued after security researchers discovered vulnerabilities during a public intrusion test in 2019.

### Key Differences
1. **Verification Approach**:
   - Swiss Post used individual verification codes rather than full cryptographic verification
   - VoteSecure uses transparent cryptographic proofs on a public bulletin board, allowing anyone to verify the election

2. **Transparency**:
   - Swiss Post's system had proprietary components
   - VoteSecure is fully open source, enabling unrestricted security analysis

3. **Security History**:
   - Swiss Post's system had significant security flaws discovered during public testing
   - VoteSecure's design uses formal methods and rigorous engineering to prevent such flaws

4. **Privacy Mechanism**:
   - Details of Swiss Post's privacy mechanism varied over different versions
   - VoteSecure uses threshold cryptography with trustees holding key shares, requiring a quorum to decrypt

## Receipt-Freeness and Coercion Resistance

**The Challenge**: Receipt-freeness means voters cannot prove how they voted, which is important to prevent vote buying and coercion. However, providing strong verifiability while preventing receipt generation is cryptographically difficult in remote voting scenarios.

### VoteSecure's Position
Like Helios, Belenios, and most practical remote E2E-V systems, VoteSecure **does not provide receipt-freeness**:
- A voter with a modified client could retain the encryption randomness
- This randomness could be used to prove how they voted
- This is an **inherent trade-off** in remote voting where the voting environment cannot be controlled

### Threat Model Acknowledgment
VoteSecure's threat model explicitly acknowledges:
- The risk of coercion in remote voting scenarios
- The impossibility of preventing receipt generation in uncontrolled environments
- The need for policy and legal measures (not just technical ones) to address coercion

### Comparison with In-Person Voting
Traditional in-person voting in controlled environments can provide better coercion resistance because:
- Voters cannot easily take devices into the voting booth
- Poll workers can observe and prevent photography
- The environment is controlled

Remote voting inherently trades some coercion resistance for accessibility and convenience.

## Trust Model

### VoteSecure
- **Privacy**: Requires a threshold of trustees to collude to break ballot privacy
- **Integrity**: Designed so that ballots cannot be changed undetectably, even with some malicious trustees
- **Verification**: Public bulletin board allows anyone to verify the correctness of the tally
- **Authentication**: Delegates to a "black box" component, allowing flexibility in deployment

### Comparison
- **Helios** and **Belenios**: Similar trust model for privacy (threshold decryption) and integrity (public verifiability)
- **Swiss Post**: Had a more complex trust model with less transparency about key management and decryption processes

## Verification Details

### Public Bulletin Board
All these systems use a public bulletin board for transparency, but with different approaches:
- **VoteSecure**: Mixing and decryption proofs are intended to be published on the public bulletin board for universal verifiability
- **Helios/Belenios**: Publish encrypted ballots and homomorphic tally proofs
- **Swiss Post**: Used a less transparent approach with verification codes

### Trustee Operations
**VoteSecure**'s approach:
- Trustees operate on an air-gapped network
- Encrypted ballots are transferred via removable storage (USB) to the trustee network
- This physical separation provides additional security against remote attacks
- Trustees jointly perform mixing and decryption with mathematical proofs

This is more secure than having trustees operate directly on Internet-connected systems but requires more operational overhead.

## Threat Model: Privacy vs. Verifiability

All E2E-V systems face similar trade-offs between privacy and verifiability:

### Privacy Threats
- **Malicious trustees**: Mitigated by threshold cryptography (requires k of n trustees to decrypt)
- **Malicious clients**: Can observe votes (receipt-freeness not provided)
- **Network observers**: Cannot learn votes (due to encryption)

### Integrity Threats  
- **Ballot box manipulation**: Prevented by cryptographic proofs and public bulletin board
- **Tally manipulation**: Prevented by verifiable mixing/homomorphic proofs
- **Malicious clients**: Can change votes, but voters can detect via ballot checking

### VoteSecure's Distinctive Approach
VoteSecure's threat model is particularly comprehensive regarding **mobile device threats**:
- Explicitly models malicious apps (e.g., TikTok) on voter devices
- Addresses cross-app security vulnerabilities
- Designs ballot checking to work on separate devices
- Assumes APTs have access to all environments

This makes VoteSecure's threat model well-suited for the realities of modern mobile voting.

## Summary Table

| Feature | VoteSecure | Helios | Belenios | Swiss Post |
|---------|-----------|---------|----------|------------|
| **Tallying** | Mixnet | Homomorphic | Homomorphic | Proprietary |
| **Receipt-free** | No | No | No | Unclear |
| **Open Source** | Yes | Yes | Yes | Partial |
| **Formal Methods** | RDE with full refinement | Some | Strong protocol verification | Limited |
| **Threat Model** | Comprehensive (APTs, mobile) | Moderate | Moderate | Unclear |
| **Ballot Checking** | Separate device supported | Same device | Same device | Verification codes |
| **Trust Model** | Threshold trustees | Threshold trustees | Threshold trustees | Complex |
| **Public BB** | Yes (with proofs) | Yes (with proofs) | Yes (with proofs) | Limited transparency |
| **Assurance Case** | Yes (for certification) | No | No | No |

## Conclusions

VoteSecure shares the fundamental cryptographic approach of other E2E-V systems (encryption, public bulletin board, cryptographic proofs) but distinguishes itself through:

1. **Rigorous Engineering**: Comprehensive formal methods from domain models to implementation
2. **Mobile-First Threat Model**: Explicit consideration of mobile device threats and APTs
3. **Workflow Compatibility**: Mixnet approach supports traditional election workflows
4. **Independent Verification**: Ballot checking designed for separate devices
5. **Assurance Case**: Structured evidence for government certification

Like all remote E2E-V systems, VoteSecure makes trade-offs:
- **Strong verifiability** vs. **receipt-freeness**: Chooses verifiability
- **Workflow compatibility** vs. **efficiency**: Chooses compatibility (via mixnet)
- **Security rigor** vs. **development speed**: Chooses rigor (via RDE)

These trade-offs align with the goal of creating a mobile voting system that can be certified and deployed by election officials in real elections.

## References

- Helios: Adida, B. (2008). "Helios: Web-based Open-Audit Voting"
- Belenios: Cortier, V., et al. (2014). "Belenios: A Simple Private and Verifiable Electronic Voting System"
- Swiss Post: Various public reports and security analyses (2019)
- VoteSecure: [Project Documentation](https://github.com/FreeAndFair/MobileVotingCoreCryptography)
- Benaloh Challenge: Benaloh, J. (2006). "Simple Verifiable Elections"

For more information about VoteSecure specifically, see:
- [Concept of Operations (CONOPS)](../docs/conops/conops.md)
- [Threat Model](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases/download/latest/threat-model.pdf)
- [FAQ](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases/download/latest/faq.pdf)
