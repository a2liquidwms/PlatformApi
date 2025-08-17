using PlatformApi.Models;

namespace PlatformApi.Emails;

public class EmailConfirmationTemplate : EmailTemplateBase
{
    private readonly string _userName;
    private readonly string _confirmationUrl;

    public EmailConfirmationTemplate(string userName, string confirmationUrl)
    {
        _userName = userName;
        _confirmationUrl = confirmationUrl;
    }

    public override string GetSubject(BrandingContext branding)
    {
        return $"Confirm Your Email Address - {branding.SiteName}";
    }

    protected override string GetEmailTitle(BrandingContext branding)
    {
        return branding.SiteName;
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<p>Hi {_userName},</p><p>Thank you for registering with {branding.SiteName}. Please confirm your email address:</p><a href=\"{_confirmationUrl}\" class=\"button\">Confirm Email Address</a><p>This link expires in 24 hours.</p><p>If you didn't request this, please ignore this email.</p><p>Your {branding.SiteName} Team</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hi {_userName},

Thank you for registering with {branding.SiteName}. Please confirm your email address:

{_confirmationUrl}

This link expires in 24 hours.

If you didn't request this, please ignore this email.

Your {branding.SiteName} Team";
    }
}