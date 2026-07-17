using System.ComponentModel;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using CAConsole.Infrastructure;
using CertificateAuthority;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAConsole.Commands;

/// <summary>
/// Answers OCSP requests with the token-resident CA key, from the same CA state
/// file that revoke/gen-crl use. One-shot file mode (--reqin/--respout) or an
/// RFC 6960 HTTP responder (--listen). Serials not in the revocation list are
/// reported good (issuance is not tracked); foreign CertIDs are unknown.
/// </summary>
public sealed class OcspRespondCommand(HsmCa hsm) : Command<OcspRespondCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("--ca-label <LABEL>")]
        [Description("Token label of the CA key pair.")]
        public required string CaLabel { get; init; }

        [CommandOption("--ca-cert <FILE>")]
        [Description("The CA certificate (PEM or DER); embedded in responses for verification.")]
        public required string CaCert { get; init; }

        [CommandOption("--state <FILE>")]
        [DefaultValue("ca-state.json")]
        public string State { get; init; } = "ca-state.json";

        [CommandOption("--validity-hours <HOURS>")]
        [Description("nextUpdate window of the responses.")]
        [DefaultValue(24)]
        public int ValidityHours { get; init; } = 24;

        [CommandOption("--reqin <FILE>")]
        [Description("File mode: DER OCSP request to answer.")]
        public string? ReqIn { get; init; }

        [CommandOption("--respout <FILE>")]
        [Description("File mode: where to write the DER OCSP response.")]
        public string? RespOut { get; init; }

        [CommandOption("--listen <PREFIX>")]
        [Description("HTTP mode: prefix to serve on, e.g. http://127.0.0.1:8080/ (POST and GET per RFC 6960).")]
        public string? Listen { get; init; }

        [CommandOption("--max-requests <N>")]
        [Description("HTTP mode: exit after N requests (0 = serve forever; mainly for testing).")]
        [DefaultValue(0)]
        public int MaxRequests { get; init; }

        [CommandOption("--pin <PIN>")]
        public string? Pin { get; init; }

        public override ValidationResult Validate()
        {
            var fileMode = ReqIn is not null || RespOut is not null;

            return (fileMode, Listen) switch
            {
                (true, not null) => ValidationResult.Error("Use either --reqin/--respout or --listen, not both."),
                (true, null) when ReqIn is null || RespOut is null =>
                    ValidationResult.Error("File mode needs both --reqin and --respout."),
                (false, null) => ValidationResult.Error("Specify --reqin/--respout (file mode) or --listen (HTTP mode)."),
                _ => ValidationResult.Success(),
            };
        }
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        using var hsmScope = hsm;
        var session = hsm.OpenLoggedInSession(settings.Pin);
        var (signer, caSpki) = hsm.LoadCaKey(session, settings.CaLabel);

        var caCertificateDer = IssueCommand.ReadDer(settings.CaCert);
        using var caCertificate = X509CertificateLoader.LoadCertificate(caCertificateDer);

        var responder = new OcspResponderService(
            caCertificate.SubjectName.RawData, caSpki, signer, caCertificateDer,
            CaStateFile.Load(settings.State), TimeSpan.FromHours(settings.ValidityHours));

        return settings.Listen is { } prefix
            ? Serve(responder, prefix, settings.MaxRequests)
            : AnswerFile(responder, settings.ReqIn!, settings.RespOut!);
    }

    private static int AnswerFile(OcspResponderService responder, string requestPath, string responsePath)
    {
        File.WriteAllBytes(responsePath, responder.Respond(File.ReadAllBytes(requestPath)));
        AnsiConsole.MarkupLine($"[green]OCSP response[/] written to [blue]{responsePath}[/].");

        return 0;
    }

    private static int Serve(OcspResponderService responder, string prefix, int maxRequests)
    {
        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix.EndsWith('/') ? prefix : $"{prefix}/");
        listener.Start();

        AnsiConsole.MarkupLine($"[green]OCSP responder[/] listening on [blue]{prefix}[/]" +
            $"{(maxRequests > 0 ? $" for {maxRequests} request(s)" : string.Empty)} — Ctrl+C to stop.");

        var served = 0;
        while (maxRequests == 0 || served < maxRequests)
        {
            var httpContext = listener.GetContext();
            served++;

            byte[] responseBytes;
            try
            {
                var requestBytes = ReadRequest(httpContext.Request);
                responseBytes = responder.Respond(requestBytes);
            }
            catch (Exception)
            {
                responseBytes = CertificateAuthority.Ocsp.OcspResponseBuilder
                    .CreateError(CertificateAuthority.Ocsp.OcspResponseStatus.InternalError);
            }

            httpContext.Response.StatusCode = 200;
            httpContext.Response.ContentType = "application/ocsp-response";
            httpContext.Response.OutputStream.Write(responseBytes);
            httpContext.Response.Close();
        }

        return 0;
    }

    private static byte[] ReadRequest(HttpListenerRequest request)
    {
        if (request.HttpMethod == "POST")
        {
            using var buffer = new MemoryStream();
            request.InputStream.CopyTo(buffer);
            return buffer.ToArray();
        }

        // RFC 6960 A.1: GET {url}/{url-encoded base64 of the DER request}
        return Convert.FromBase64String(WebUtility.UrlDecode(request.Url!.AbsolutePath.TrimStart('/')));
    }
}
