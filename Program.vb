Imports System
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.Json

Module Program
    Sub Main(args As String())
        If args.Contains("--test-vectors") Then
            KernAuth.RunVectors()
            Return
        End If
        Dim app = New KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__")
        Dim key = LicenseKey()
        If Not app.Validate(key).GetAwaiter().GetResult() Then
            Console.WriteLine(app.Message)
            Environment.Exit(1)
        End If
        Using features = JsonDocument.Parse(app.Features)
            Dim payloadKey = Unwrap(features.RootElement)
            If payloadKey Is Nothing Then
                Console.WriteLine("The payload key could not open this build.")
                Environment.Exit(1)
            End If
            CryptographicOperations.ZeroMemory(payloadKey)
            ' Decrypt the program with the opened key. Drop it when the heartbeat fails.
            Console.WriteLine("Payload opened")
            Console.WriteLine($"Status: {app.Status}")
            Console.WriteLine($"License: {app.LicenseId}")
            Console.WriteLine($"Check expires: {app.ExpiresAt}")
        End Using
        While True
            Threading.Thread.Sleep(60000)
            Try
                app.Heartbeat(key).GetAwaiter().GetResult()
            Catch ex As Exception
                Console.WriteLine(ex.Message)
                Environment.Exit(1)
            End Try
        End While
    End Sub

    Function Unwrap(features As JsonElement) As Byte()
        Dim wrapElement As JsonElement = Nothing
        Dim boxElement As JsonElement = Nothing
        If Not features.TryGetProperty("wrap_key", wrapElement) _
            OrElse Not features.TryGetProperty("payload_box", boxElement) _
            OrElse wrapElement.ValueKind <> JsonValueKind.String _
            OrElse boxElement.ValueKind <> JsonValueKind.String Then
            Return Nothing
        End If
        Try
            Dim wrapKey = Convert.FromBase64String(wrapElement.GetString())
            Dim box = Convert.FromBase64String(boxElement.GetString())
            If wrapKey.Length <> 32 OrElse box.Length <= 28 Then Return Nothing
            Dim nonce = box.AsSpan(0, 12)
            Dim cipher = box.AsSpan(12, box.Length - 28)
            Dim tag = box.AsSpan(box.Length - 16)
            Dim payloadKey = New Byte(cipher.Length - 1) {}
            Using aes As New AesGcm(wrapKey, 16)
                aes.Decrypt(nonce, cipher, tag, payloadKey)
            End Using
            If payloadKey.Length = 0 Then Return Nothing
            Return payloadKey
        Catch
            Return Nothing
        End Try
    End Function

    Function LicenseKey() As String
        Dim fromEnv = Environment.GetEnvironmentVariable("KERN_LICENSE_KEY")
        If Not String.IsNullOrWhiteSpace(fromEnv) Then Return fromEnv.Trim()
        If Not Console.IsInputRedirected Then Console.Write("Enter license: ")
        Dim entered = Console.ReadLine()
        If entered Is Nothing Then Return ""
        Return entered.Trim()
    End Function
End Module
