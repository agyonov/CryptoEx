# About CryptoEx project

This project provides a couple of .NET / C# libraries for cryptographically signing and verifying data using .NET in some advanced scenarios.

As the name ***CryptoEx*** suggests it can be think of both as *Extension* of and *Example* of usage of the standard capabilities provided by the .NET platform in areas as:
- XML digital signatures - [XML Signature Syntax and Processing Version 1.1](https://www.w3.org/TR/xmldsig-core/)
- JSON digital signatures - [JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515)
- EdDsa (Ed25519 and Ed448)
- Advanced Electronic Signatures and Infrastructures standardized by the European Union, so called ***jAdES*** & ***xAdES*** 

## Important disclaimer

This project **does not** have an intention to be a full-featured library to fully implement all possible implementations and applications in all possible scenarios for digital signatures (In my humble opinion it is not feasible option anyway). Rather than that it's purpose is to be used as a reference (or example if you prefer) of how to achieve some tasks using platforms abilities in some areas and how to extend minor platform gaps in other areas.

### Example areas and gaps 

**For example in XML signatures** area there is mature (and not very much evolving) library provided by the platform itself [System.Security.Cryptography.Xml](https://www.nuget.org/packages/System.Security.Cryptography.Xml/), but in my personal experience there are two major issues with it:
1. Examples and documentation are messy - You may easily see from Microsoft's docs how to do basic sign / verify of an enveloped XML message, but you will be in trouble finding "official" docs and examples on some more advanced scenarios like - *detached* signatures or signing additional *References* XML data 
2. The basic library also lacks some algorithms that are part of the XML digital signature specification - namely the ones with EcDSA.

Now this might be annoying flaws, but also there are to some extend "natural" (the all possible implementations, ways to implement XML signing, is vast area, because of the "opened" specification) or easy to overcome. So, in the current project I have extended the standard library to support the missing algorithms and have provided some implementations to show as an example how to sign *Detached* data and additional *Reference* XML elements.

You can check the code and some pages in the [Wiki](https://github.com/agyonov/CryptoEx/wiki).

You can freely use it as an example and further amend or extend the code to suit your particular needs as possible applications are vast.

**Other example is the JSON Web signatures** area. In this domain there are few open source libraries but their focus is either JSON Web Tokens (that are private case of the broader JSON Web Signatures) or limited in application for [jAdES](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf).

In the current project you can find an implementation of [RFC 7515 (JSON Web Signatures)](https://www.rfc-editor.org/rfc/rfc7515.html) and practical implementation for the European Union's *Advanced digital signatures*, that builds on top of [RFC 7515 (JSON Web Signatures)](https://www.rfc-editor.org/rfc/rfc7515.html).

Please, check the code and the corresponding [Wiki Pages](https://github.com/agyonov/CryptoEx/wiki).

Again, you are free and encouraged to use these as an example or to extend these to suit you purposes in a better way.

