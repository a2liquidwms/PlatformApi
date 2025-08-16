using PlatformApi.Models;

namespace PlatformApi.Emails;

public class WelcomeEmailTemplate : EmailTemplateBase
{
    private readonly string _userName;

    public WelcomeEmailTemplate(string userName)
    {
        _userName = userName;
    }

    public override string GetSubject(BrandingContext branding)
    {
        return $"Welcome to {branding.SiteName}!";
    }

    protected override string GetEmailTitle()
    {
        return "Welcome!";
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $@"
            <h2>Hello {_userName}!</h2>
            <p>Your email has been successfully confirmed and your {branding.SiteName} account is now active.</p>
            <p><strong>Thank you for choosing {branding.SiteName}!</strong></p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hello {_userName}!

Welcome to {branding.SiteName}! Your email has been successfully confirmed and your account is now active.

Thank you for choosing {branding.SiteName}!

Best regards,
{branding.SiteName}";
    }
}