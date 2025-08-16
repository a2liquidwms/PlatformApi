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

    protected override string GetEmailTitle()
    {
        return "Confirm Your Email Address";
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<h2>Hello {_userName}!</h2><p>Thank you for registering with {branding.SiteName}. To complete your registration, please confirm your email address by clicking the button below:</p><div class=\"center\"><a href=\"{_confirmationUrl}\" class=\"button\">Confirm Email Address</a></div><p>If the button doesn't work, you can copy and paste this link into your browser:</p><div class=\"url-box\">{_confirmationUrl}</div><p><strong>Important:</strong> This link will expire in 24 hours for security reasons.</p><p>If you didn't request this email, please ignore it.</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hello {_userName}!

Thank you for registering with {branding.SiteName}. To complete your registration, please confirm your email address by visiting the following link:

{_confirmationUrl}

This link will expire in 24 hours for security reasons.

If you didn't request this email, please ignore it.

Best regards,
{branding.SiteName} Team";
    }
}