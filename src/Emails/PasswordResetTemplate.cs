using PlatformApi.Models;

namespace PlatformApi.Emails;

public class PasswordResetTemplate : EmailTemplateBase
{
    private readonly string _userName;
    private readonly string _resetUrl;

    public PasswordResetTemplate(string userName, string resetUrl)
    {
        _userName = userName;
        _resetUrl = resetUrl;
    }

    public override string GetSubject(BrandingContext branding)
    {
        return $"{branding.SiteName} Password Reset";
    }


    protected override string GetEmailTitle(BrandingContext branding)
    {
        return branding.SiteName;
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<p>Hi {_userName},</p><p>Need to reset your {branding.SiteName} password? No problem. Just click this link:</p><a href=\"{_resetUrl}\" class=\"button\">Reset Password</a><p>This link expires in 1 hour.</p><p>If you didn't request this, please ignore this email.</p><p>Your {branding.SiteName} Team</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hi {_userName},

Need to reset your {branding.SiteName} password? No problem. Just click this link:

{_resetUrl}

This link expires in 1 hour.

If you didn't request this, please ignore this email.

Your {branding.SiteName} Team";
    }
}