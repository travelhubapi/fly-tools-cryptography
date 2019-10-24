# Flytour Tools Cryptography

A simple way to encrypt data for communication with Travelhub.

Flytour Tools Cryptography is available for download and installation as
[NuGet packages](https://www.nuget.org/packages/Flytour.Tools.Cryptography/).

## Building

To build Flytour Tools Cryptography from sources, you will need:

[.NET Core 3.0 SDK](release-notes/3.0/README.md)

## Operators

### Encrypt

````c#
var pem = @"-----BEGIN PUBLIC KEY-----
			MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxIRs8RmdAKypl9tKhrty
			rjwYn1hsVebAHkZjPiSwRBTZF7uLzotYPRgKFiV8sUo6RKvNT9wab+NE0LnyC/wz
			132Q5cQrxkeNey8r+1Q3QaGSRXLifvn8BSrgATJm+VbMTMGTTtMc5XLbrH9natbd
			POxDgJIy31+0Oets8/+EQPKNT/CeicfmuSlI+jo5Jcds8rpOURLEW9dcTY69TLpv
			YhjCYlT68pGLf/zrMFgbp2T4ax9iI1YBZA2MTkLC323b2VB8kYu1lN2pn3mvQFH/
			n2eahmSciHaOvs4fIqNlcyNi0tjRZC4++ejdW2Qsy5+j1DxOURY7KmvicqpVYw21
			0QIDAQAB
			-----END PUBLIC KEY-----";

AsymmetricProvider.Encrypt("value", pem);

````

