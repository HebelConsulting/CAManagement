using System.ComponentModel;
using CertificateAuthority.Analysis;
using Spectre.Console;
using Spectre.Console.Cli;

namespace CAConsole.Commands;

/// <summary>certutil-style ASN.1 analysis: structure tree left, explanations right.</summary>
public sealed class AsnCommand : Command<AsnCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandArgument(0, "<file>")]
        [Description("Certificate, CSR, CRL, public or private key file (PEM or DER).")]
        public required string File { get; init; }

        [CommandOption("--index <N>")]
        [Description("1-based PEM block to analyze when the file contains several (e.g. a CA bundle).")]
        [DefaultValue(1)]
        public int Index { get; init; } = 1;
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var document = Load(settings);

        AnsiConsole.MarkupLine($"Detected: [bold green]{document.Kind}[/]");

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Structure");
        table.AddColumn("Explanation");

        AddRows(table, document.Root, depth: 0);
        AnsiConsole.Write(table);

        return 0;
    }

    private static AnalyzedDocument Load(Settings settings)
    {
        var bytes = System.IO.File.ReadAllBytes(settings.File);

        if (bytes.AsSpan().IndexOf("-----BEGIN"u8) < 0)
        {
            return Asn1Analyzer.Analyze(bytes); // raw DER
        }

        var blocks = CertificateAuthority.Pem.DecodeAll(System.Text.Encoding.UTF8.GetString(bytes));
        if (blocks.Count == 0)
        {
            throw new FormatException($"'{settings.File}' contains no decodable PEM block.");
        }

        if (settings.Index < 1 || settings.Index > blocks.Count)
        {
            throw new ArgumentOutOfRangeException(nameof(settings.Index),
                $"--index must be between 1 and {blocks.Count} for this file.");
        }

        var (label, der) = blocks[settings.Index - 1];

        if (blocks.Count > 1)
        {
            AnsiConsole.MarkupLine(
                $"File contains [bold]{blocks.Count}[/] PEM blocks; analyzing block [bold]{settings.Index}[/] ({label}). " +
                "Use [blue]--index[/] to pick another.");
        }

        return Asn1Analyzer.AnalyzeDer(der, label);
    }

    private static void AddRows(Table table, Asn1Node node, int depth)
    {
        var indent = new string(' ', depth * 2);
        var value = node.Value is { } v ? $" [white]{Markup.Escape(v)}[/]" : string.Empty;
        var structure = $"[dim]{node.Offset,5}[/] {indent}[cyan]{Markup.Escape(node.TagName)}[/]{value}";

        var explanation = node switch
        {
            { Name: { } name, Explanation: { } text } => $"[bold]{Markup.Escape(name)}[/] — {Markup.Escape(text)}",
            { Name: { } name } => $"[bold]{Markup.Escape(name)}[/]",
            _ => string.Empty,
        };

        table.AddRow(structure, explanation);

        foreach (var child in node.Children)
        {
            AddRows(table, child, depth + 1);
        }
    }
}
