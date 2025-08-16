using PlatformApi.Models;

namespace PlatformApi.Emails;

public interface IEmailTemplate
{
    string GenerateHtml(BrandingContext branding);
    string GenerateText(BrandingContext branding);
    string GetSubject(BrandingContext branding);
}