namespace PlatformApi.Models;

public class EmailContent
{
    public required string ToEmail { get; set; }
    public required string Subject { get; set; }
    public required string HtmlBody { get; set; }
    public string? TextBody { get; set; }
    public required BrandingContext Branding { get; set; }
}