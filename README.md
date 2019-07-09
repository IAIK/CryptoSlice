CryptoSlice
===========

This repository contains the implementation of a framework to automatically disclose security-critical implementation weaknesses in Android applications.

It represents our solution to:

- Apply static slicing in forward and backward direction on pre-definable patterns. The resulting execution traces model the information flow of relevant code segments and can be further inspected.
- Highlight the improper usage of security-relevant functionality. By analyzing data flows using an extensible set of security rules, we find problematic statements, can pinpoint their exact origin in code, and find appendant invocations.
- Track the data flow of user input in forward direction and determine how it is processed. 

Backward slicing enables us to evaluate the values of parameters passed to cryptographic and security-related APIs: 
> [Paper](https://pure.tugraz.at/ws/portalfiles/portal/23858147): "A Comparative Study of Misapplied Cryptoin Android and iOS Applications" by Johannes Feichtner,
presented at SECRYPT 2019.

Forward slicing can be used to follow the trace of a password right from the point where it enters an application:
> [Paper](https://pure.tugraz.at/ws/portalfiles/portal/19449611): "Hunting Password Leaks in Android Applications" by Johannes Feichtner,
presented at IFIP SEC 2018.

**Note:** *This code is provided as-is. You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. It may or may not detect vulnerabilities in your application/OS or device. It is intended only for educational purposes.*
