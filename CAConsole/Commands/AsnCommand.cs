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
    }

    public override int Execute(CommandContext context, Settings settings)
    {
        var document = Asn1Analyzer.Analyze(System.IO.File.ReadAllBytes(settings.File));

        AnsiConsole.MarkupLine($"Detected: [bold green]{document.Kind}[/]");

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Structure");
        table.AddColumn("Explanation");

        AddRows(table, document.Root, depth: 0);
        AnsiConsole.Write(table);

        return 0;
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
