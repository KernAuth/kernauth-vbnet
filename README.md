# KernAuth VB.NET example

Paste the public app ID and public key from Developers into `Program.vb`. .NET 8, with BouncyCastle.Cryptography.

## Instance

```vb
Dim app = New KernAuth(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__PUBLIC_KEY__")
```

## Validate

```vb
If Not Await app.Validate(license, installation) Then
    Throw New Exception(app.Message)
End If
Console.WriteLine($"Status: {app.Status}")
Console.WriteLine($"Features: {app.Features}")
Console.WriteLine($"License: {app.LicenseId}")
Console.WriteLine($"Check expires: {app.ExpiresAt}")
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID. The program then asks the server again every minute. If the session was ended, the key was paused, or this computer is blocked, it prints that message and exits.

## Run

```
dotnet run -- --test-vectors
dotnet run
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
