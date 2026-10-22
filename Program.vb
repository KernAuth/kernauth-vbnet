Imports System
Imports System.Linq

Module Program
    Sub Main(args As String())
        If args.Contains("--test-vectors") Then
            KernAuth.RunVectors()
            Return
        End If
        Dim app = New KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__", "__PUBLIC_KEY__")
        If Not app.Initialize().GetAwaiter().GetResult() Then
            Console.WriteLine(app.Message)
            Environment.Exit(1)
        End If
        Dim key = LicenseKey()
        If Not app.Validate(key).GetAwaiter().GetResult() Then
            Console.WriteLine(app.Message)
            Environment.Exit(1)
        End If
        app.Features = ""
        Console.WriteLine($"Status: {app.Status}")
        Console.WriteLine($"License: {app.LicenseId}")
        Console.WriteLine($"Check expires: {app.ExpiresAt}")
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

    Function LicenseKey() As String
        Dim fromEnv = Environment.GetEnvironmentVariable("KERN_LICENSE_KEY")
        If Not String.IsNullOrWhiteSpace(fromEnv) Then Return fromEnv.Trim()
        If Not Console.IsInputRedirected Then Console.Write("Enter license: ")
        Dim entered = Console.ReadLine()
        If entered Is Nothing Then Return ""
        Return entered.Trim()
    End Function
End Module
