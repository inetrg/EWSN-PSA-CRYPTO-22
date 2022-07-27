# Usable Security for an IoT OS: Integrating the Zoo of Embedded Crypto Components Below a Common API

[![Paper][paper-badge]][paper-link]
[![Preprint][preprint-badge]][preprint-link]

This repository contains code and documentation to reproduce experimental results of the paper **"[Usable Security for an IoT OS: Integrating the Zoo of Embedded Crypto Components Below a Common API][preprint-link]"** published in Proc. of the EWSN Conference 2022.

* Lena Boeckmann, Peter Kietzmann, Leandro Lanzieri, Thomas C. Schmidt, Matthias Wählisch,
**Usable Security for an IoT OS: Integrating the Zoo of Embedded Crypto Components Below a Common API**,
In: International Conference on Embedded Wireless Systems and Networks (EWSN'22), ACM: New York, USA, October 2022.

 **Abstract**
 > IoT devices differ widely in crypto-supporting hardware, ranging from no hardware support to powerful accelerators supporting numerous of operations including protected key storage. An operating system should provide uniform access to these heterogeneous hardware features, which is a particular challenge in the resource constrained IoT. Effective security is tied to the usability of cryptographic interfaces. A thoughtful API design is challenging, and it is beneficial to re-use such an interface and to share the knowledge of programming embedded security widely. In this paper, we integrate an emerging cryptographic interface into usable system-level calls for the IoT operating system RIOT, which runs on more than 200 platforms. This interface supports ID-based key handling to access key material in protected storage without exposing it to anyone. Our design foresees hardware acceleration on all available variants; our implementation integrates diverse cryptographic hardware and software backends via the uniform interface. Our performance measurements show that the overhead of the uniform API with integrated key management is negligible compared to the individual crypto operation. Our approach enhances the usability, portability, and flexibility of cryptographic support in the IoT.

Please follow our [Getting Started](getting_started.md) instructions for further information how to compile and execute the code.

<!-- TODO: update URLs -->
[paper-link]:#
[preprint-link]:#
[paper-badge]: #
[preprint-badge]: #