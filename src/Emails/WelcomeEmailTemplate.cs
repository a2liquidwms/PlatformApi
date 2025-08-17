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

    protected override string GetEmailTitle(BrandingContext branding)
    {
        return branding.SiteName;
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<p>Hi {_userName},</p><p>Welcome to {branding.SiteName}! Your account is now active.</p><p>Thank you for choosing {branding.SiteName}!</p><p>Your {branding.SiteName} Team</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hi {_userName},

Welcome to {branding.SiteName}! Your account is now active.

Thank you for choosing {branding.SiteName}!

Your {branding.SiteName} Team";
    }
}