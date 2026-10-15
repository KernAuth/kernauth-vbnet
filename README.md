# KernAuth VB.NET example

Example for .NET 8. This file calls validate and checks the Ed25519 signature with BouncyCastle.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `Program.vb`.

```
dotnet run -- --test-vectors
```

Run from the repository root so the test can read `vectors.json`. Run the example with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```vb
Dim app = New KernAuth(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__KEY_ID__",
    "__PUBLIC_KEY__")
```

## Validate

```vb
If Not Await app.Validate(license, installation) Then
    Throw New Exception(app.Message)
End If
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
