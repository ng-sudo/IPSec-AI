# PS 26160 — IPSecAI

## Project

AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework.

## Objective

Build a software platform that analyzes IPsec VPN traffic and performs AI-assisted protocol identification, encrypted traffic classification, and automated security assessment.

## Core requirements

The system must support:

1. IPsec VPN testbed generation

   * Tunnel mode
   * Transport mode
   * AES-128
   * AES-256
   * AES-GCM
   * AES-CBC + HMAC
   * Multiple DH groups
   * PFS enabled/disabled
   * IPv4
   * IPv6
   * Multiple traffic types

2. Traffic capture

   * IKE
   * ESP
   * Optional AH
   * Normal communication traffic

3. AI-based protocol identification

   * IPsec identification
   * IKE version
   * Tunnel/Transport mode
   * Encryption algorithm
   * Authentication algorithm
   * Key exchange
   * Security Association characteristics
   * Encrypted ESP traffic-type prediction

4. Security assessment

   * Cryptographic strength
   * Configuration compliance
   * SA parameters
   * Key lifetime
   * Replay protection
   * PFS
   * Cipher-suite strength
   * Metadata exposure

5. Output

   * Security score
   * Risk score
   * Traffic analysis
   * Metadata inference
   * Threat matrix
   * AI confidence score
   * Executive report
   * Technical report

6. Required project deliverables

   * Working prototype
   * AI classification engine
   * Interactive dashboard
   * Assessment reports
   * Training/testing dataset
   * Documentation
   * Demonstration

## Architecture principles

* Use Python for packet analysis, backend services and ML.
* Use FastAPI for backend APIs.
* Use React for the dashboard.
* Use PostgreSQL for structured metadata.
* Use PCAP files as packet-analysis inputs.
* Use Scapy/tshark/tcpdump/Wireshark-compatible tooling for packet analysis.
* Use a Linux IPsec implementation such as strongSwan for the controlled testbed.
* Use scikit-learn and/or gradient-boosting models for initial ML development.
* Keep packet parsing, ML inference, security assessment and UI separate.
* Use a hybrid architecture: deterministic protocol/security analysis + ML inference.
* Every AI prediction must expose a confidence score.
* Every security finding must contain evidence and a rationale.

## Important development rules

Do not:

* build unrelated cybersecurity tools;
* turn the project into a generic SIEM;
* add malware analysis;
* add vulnerability scanning unrelated to IPsec;
* add a generic chatbot;
* claim AI capabilities that are actually rule-based;
* fabricate model accuracy;
* use placeholder results in the final implementation;
* hard-code fake PCAP analysis results.

Implement one module at a time and test it before moving to the next module.

Before making major architectural changes, inspect the existing repository and preserve established interfaces unless there is a documented reason to change them.
