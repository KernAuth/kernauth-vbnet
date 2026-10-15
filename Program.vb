Imports System.IO
Imports System.Linq
Imports System.Net.Http
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.Json
Imports System.Threading.Tasks
Imports Org.BouncyCastle.Crypto.Parameters
Imports Org.BouncyCastle.Crypto.Signers

Module Program
    Private Const Api As String = "https://api.kernauth.com"
    Private Const AppId As String = "__PUBLIC_APP_ID__"
    Private Const PublicKey As String = "__PUBLIC_KEY__"

    Sub Main(args As String())
        If args.Contains("--test-vectors") Then
            Vectors()
            Return
        End If
        Dim app = New KernAuth(Api, AppId, PublicKey)
        Dim key = LicenseKey()
        Dim hwid = InstallationId()
        If Not app.Validate(key, hwid).GetAwaiter().GetResult() Then Throw New Exception(app.Message)
        Console.WriteLine($"Status: {app.Status}")
        Console.WriteLine($"Features: {app.Features}")
        Console.WriteLine($"License: {app.LicenseId}")
        Console.WriteLine($"Check expires: {app.ExpiresAt}")
        While True
            Threading.Thread.Sleep(60000)
            Try
                app.Heartbeat(key, hwid).GetAwaiter().GetResult()
            Catch ex As Exception
                Console.WriteLine(ex.Message)
                Environment.Exit(1)
            End Try
        End While
    End Sub

    Function LicenseKey() As String
        Dim fromEnv = Environment.GetEnvironmentVariable("KERN_LICENSE_KEY")
        If Not String.IsNullOrWhiteSpace(fromEnv) Then Return fromEnv.Trim()
        If Not Console.IsInputRedirected Then Console.Write("Enter license: ")
        Dim entered = Console.ReadLine()
        If entered Is Nothing Then Return ""
        Return entered.Trim()
    End Function

    Function InstallationId() As String
        Dim fromEnv = Environment.GetEnvironmentVariable("KERN_INSTALLATION_ID")
        If Not String.IsNullOrWhiteSpace(fromEnv) Then Return fromEnv.Trim()
        Dim hwid = MachineHwid().Trim()
        If AcceptableHwid(hwid) Then Return hwid
        Throw New Exception("Could not read the HWID")
    End Function

    Function AcceptableHwid(value As String) As Boolean
        If value.Length < 8 OrElse value.Length > 64 Then Return False
        For Each cell In value
            Dim ok = (cell >= "A"c AndAlso cell <= "Z"c) OrElse (cell >= "a"c AndAlso cell <= "z"c) OrElse (cell >= "0"c AndAlso cell <= "9"c) OrElse cell = "_"c OrElse cell = "-"c
            If Not ok Then Return False
        Next
        Return True
    End Function

    Function MachineHwid() As String
        If OperatingSystem.IsWindows() Then
            Dim user = System.Security.Principal.WindowsIdentity.GetCurrent().User
            If user Is Nothing Then Return ""
            Return user.Value
        End If
        If OperatingSystem.IsLinux() Then Return File.ReadAllText("/etc/machine-id")
        If Not OperatingSystem.IsMacOS() Then Return ""
        Dim process = System.Diagnostics.Process.Start(New System.Diagnostics.ProcessStartInfo With {
            .FileName = "ioreg", .Arguments = "-rd1 -c IOPlatformExpertDevice", .RedirectStandardOutput = True, .UseShellExecute = False
        })
        Dim output = If(process?.StandardOutput.ReadToEnd(), "")
        Dim marker = """IOPlatformUUID"" = """
        Dim start = output.IndexOf(marker, StringComparison.Ordinal)
        If start < 0 Then Return ""
        start += marker.Length
        Dim ending = output.IndexOf(""""c, start)
        If ending < 0 Then Return ""
        Return output.Substring(start, ending - start)
    End Function

    Sub Vectors()
        Dim vectorPath = Path.GetFullPath("vectors.json")
        Using fixture = JsonDocument.Parse(File.ReadAllText(vectorPath))
            For Each vector In fixture.RootElement.GetProperty("vectors").EnumerateArray()
                Dim ent = vector.GetProperty("fields")
                If Encoding.UTF8.GetString(KernAuth.Canonical(ent)) <> vector.GetProperty("canonical").GetString() Then Throw New Exception("Canonical bytes differ")
                Using grant = JsonDocument.Parse(JsonSerializer.Serialize(New With {
                    .entitlement = ent, .signature = vector.GetProperty("signature").GetString()
                }))
                    Dim nonce = ent.GetProperty("nonce").GetString()
                    Dim name = ent.GetProperty("application_id").GetString()
                    Dim pinned = vector.GetProperty("public_key").GetString()
                    Dim now = DateTimeOffset.Parse("2026-01-01T00:01:00Z")
                    If Not KernAuth.Verify(grant.RootElement, nonce, name, pinned, now) OrElse
                        KernAuth.Verify(grant.RootElement, "wrong", name, pinned, now) OrElse
                        KernAuth.Verify(grant.RootElement, nonce, "pub_other_app", pinned, now) OrElse
                        KernAuth.Verify(grant.RootElement, nonce, name, pinned, DateTimeOffset.Parse(ent.GetProperty("expires_at").GetString())) Then
                        Throw New Exception("Vector verification failed")
                    End If
                End Using
                Using forged = JsonDocument.Parse(JsonSerializer.Serialize(New With {
                    .entitlement = ent, .signature = vector.GetProperty("signature").GetString() & "AA"
                }))
                    If KernAuth.Verify(forged.RootElement, ent.GetProperty("nonce").GetString(), ent.GetProperty("application_id").GetString(), vector.GetProperty("public_key").GetString(), DateTimeOffset.Parse("2026-01-01T00:01:00Z")) Then
                        Throw New Exception("Bad signature accepted")
                    End If
                End Using
                Dim tampered = ent.GetRawText().Replace("""device_id"": ""dev_vector_0001""", """device_id"": ""other""", StringComparison.Ordinal)
                If tampered = ent.GetRawText() Then Throw New Exception("Device field was not replaced")
                Using badDevice = JsonDocument.Parse("{""entitlement"":" & tampered & ",""signature"":""" & vector.GetProperty("signature").GetString() & """}")
                    If KernAuth.Verify(badDevice.RootElement, ent.GetProperty("nonce").GetString(), ent.GetProperty("application_id").GetString(), vector.GetProperty("public_key").GetString(), DateTimeOffset.Parse("2026-01-01T00:01:00Z")) Then
                        Throw New Exception("Tampered device accepted")
                    End If
                End Using
            Next
        End Using
        Console.WriteLine("VB.NET vectors passed")
    End Sub
End Module

Public Class KernAuth
    Private Shared ReadOnly Fields As String() = {
        "protocol_version", "entitlement_id", "application_id", "license_id", "status",
        "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"
    }

    Public ReadOnly Property Api As String
    Public ReadOnly Property AppId As String
    Public ReadOnly Property PublicKey As String
    Public Property Success As Boolean
    Public Property Message As String = ""
    Public Property Status As String = ""
    Public Property Features As String = ""
    Public Property LicenseId As String = ""
    Public Property ExpiresAt As String = ""

    Public Sub New(api As String, appId As String, publicKey As String)
        Me.Api = api
        Me.AppId = appId
        Me.PublicKey = publicKey
    End Sub

    Public Function Validate(license As String, installation As String) As Task(Of Boolean)
        Return CallMode("validate", license, installation, "License is active")
    End Function

    Public Async Function Heartbeat(license As String, installation As String) As Task
        Dim nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant()
        Dim fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"kernauth-device-v1:{installation}"))).ToLowerInvariant()
        Dim body = JsonSerializer.Serialize(New With {
            .protocol_version = 1, .public_app_id = AppId, .client_version = "1.0.0", .license_key = license,
            .fingerprint_version = 1, .device_fingerprint = fingerprint, .installation_id = installation, .nonce = nonce
        })
        Using client As New HttpClient()
            client.Timeout = TimeSpan.FromSeconds(10)
            Using response = Await client.PostAsync($"{Api}/v1/client/heartbeat", New StringContent(body, Encoding.UTF8, "application/json"))
                Dim text = Await response.Content.ReadAsStringAsync()
                If Not response.IsSuccessStatusCode Then Throw New Exception(ApiMessage(text, $"heartbeat failed ({CInt(response.StatusCode)})"))
                Using parsed = JsonDocument.Parse(text)
                    Dim ok As JsonElement = Nothing
                    If Not parsed.RootElement.TryGetProperty("ok", ok) OrElse ok.ValueKind <> JsonValueKind.True Then
                        Throw New Exception("heartbeat failed")
                    End If
                End Using
            End Using
        End Using
    End Function

    Private Shared Function ApiMessage(raw As String, fallback As String) As String
        Try
            Using parsed = JsonDocument.Parse(raw)
                Dim message As JsonElement = Nothing
                Dim errorNode As JsonElement = Nothing
                If parsed.RootElement.TryGetProperty("error", errorNode) AndAlso errorNode.TryGetProperty("message", message) AndAlso message.ValueKind = JsonValueKind.String AndAlso Not String.IsNullOrWhiteSpace(message.GetString()) Then
                    Return message.GetString()
                End If
            End Using
        Catch
        End Try
        Return fallback
    End Function

    Private Async Function CallMode(mode As String, license As String, installation As String, okMessage As String) As Task(Of Boolean)
        Try
            Await Post(mode, license, installation)
            Success = True
            Message = okMessage
            Return True
        Catch ex As Exception
            Success = False
            Message = ex.Message
            Return False
        End Try
    End Function

    Private Async Function Post(mode As String, license As String, installation As String) As Task
        Dim nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant()
        Dim fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"kernauth-device-v1:{installation}"))).ToLowerInvariant()
        Dim body = JsonSerializer.Serialize(New With {
            .protocol_version = 1, .public_app_id = AppId, .client_version = "1.0.0", .license_key = license,
            .fingerprint_version = 1, .device_fingerprint = fingerprint, .installation_id = installation, .nonce = nonce
        })
        Using client As New HttpClient()
            client.Timeout = TimeSpan.FromSeconds(10)
            Using response = Await client.PostAsync($"{Api}/v1/client/{mode}", New StringContent(body, Encoding.UTF8, "application/json"))
                Dim text = Await response.Content.ReadAsStringAsync()
                If Not response.IsSuccessStatusCode Then Throw New Exception(ApiMessage(text, $"{mode} failed ({CInt(response.StatusCode)})"))
                Using parsed = JsonDocument.Parse(text)
                    If Not Verify(parsed.RootElement, nonce, AppId, PublicKey, DateTimeOffset.UtcNow) Then
                        Throw New Exception("Invalid or expired signed entitlement")
                    End If
                    Dim ent = parsed.RootElement.GetProperty("entitlement")
                    Status = If(ent.GetProperty("status").GetString(), "")
                    Dim feature = ent.GetProperty("features")
                    Features = CanonicalFeatures(If(feature.ValueKind = JsonValueKind.String, JsonDocument.Parse(feature.GetString()).RootElement, feature))
                    LicenseId = If(ent.GetProperty("license_id").GetString(), "")
                    ExpiresAt = If(ent.GetProperty("expires_at").GetString(), "")
                End Using
            End Using
        End Using
    End Function

    Public Shared Function Canonical(entitlement As JsonElement) As Byte()
        Dim lines As New StringBuilder()
        For Each name In Fields
            Dim element = entitlement.GetProperty(name)
            Dim value = If(name = "features", CanonicalFeatures(If(element.ValueKind = JsonValueKind.String, JsonDocument.Parse(element.GetString()).RootElement, element)), If(element.ValueKind = JsonValueKind.String, element.GetString(), element.GetRawText()))
            If value.Contains(ChrW(10)) OrElse value.Contains(ChrW(13)) Then Throw New InvalidDataException("Invalid entitlement field")
            lines.Append(name).Append("="c).Append(value).Append(ChrW(10))
        Next
        Return Encoding.UTF8.GetBytes(lines.ToString())
    End Function

    Private Shared Function CanonicalFeatures(input As JsonElement) As String
        Using stream As New MemoryStream()
            Using writer As New Utf8JsonWriter(stream)
                WriteSorted(writer, input)
            End Using
            Return Encoding.UTF8.GetString(stream.ToArray())
        End Using
    End Function

    Private Shared Sub WriteSorted(writer As Utf8JsonWriter, element As JsonElement)
        If element.ValueKind = JsonValueKind.Object Then
            writer.WriteStartObject()
            For Each prop In element.EnumerateObject().OrderBy(Function(item) item.Name, StringComparer.Ordinal)
                writer.WritePropertyName(prop.Name)
                WriteSorted(writer, prop.Value)
            Next
            writer.WriteEndObject()
        ElseIf element.ValueKind = JsonValueKind.Array Then
            writer.WriteStartArray()
            For Each item In element.EnumerateArray()
                WriteSorted(writer, item)
            Next
            writer.WriteEndArray()
        Else
            element.WriteTo(writer)
        End If
    End Sub

    Public Shared Function Verify(grant As JsonElement, nonce As String, expectedApp As String, pinnedKey As String, now As DateTimeOffset) As Boolean
        Try
            Dim ent = grant.GetProperty("entitlement")
            If ent.GetProperty("protocol_version").GetInt32() <> 1 OrElse
                ent.GetProperty("nonce").GetString() <> nonce OrElse
                ent.GetProperty("application_id").GetString() <> expectedApp OrElse
                ent.GetProperty("status").GetString() <> "active" OrElse
                DateTimeOffset.Parse(ent.GetProperty("expires_at").GetString()) <= now Then Return False
            Dim key = New Ed25519PublicKeyParameters(Convert.FromBase64String(pinnedKey), 0)
            Dim signature = Convert.FromBase64String(grant.GetProperty("signature").GetString())
            Dim message = Canonical(ent)
            Dim verifier = New Ed25519Signer()
            verifier.Init(False, key)
            verifier.BlockUpdate(message, 0, message.Length)
            Return verifier.VerifySignature(signature)
        Catch
            Return False
        End Try
    End Function
End Class
