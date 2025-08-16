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
        return $"Reset Your Password - {branding.SiteName}";
    }

    protected override string GetEmailTitle()
    {
        return "Reset Your Password";
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<h2>Hello {_userName}!</h2><p>We received a request to reset your password for your {branding.SiteName} account. If you made this request, click the button below to reset your password:</p><div class=\"center\"><a href=\"{_resetUrl}\" class=\"button\">Reset Password</a></div><p>If the button doesn't work, you can copy and paste this link into your browser:</p><div class=\"url-box\">{_resetUrl}</div><div class=\"warning\"><strong>Security Notice:</strong> This link will expire in 1 hour for security reasons. If you didn't request this password reset, please ignore this email and your password will remain unchanged.</div><p>If you have any concerns about your account security, please contact our support team.</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hello {_userName}!

We received a request to reset your password for your {branding.SiteName} account. If you made this request, visit the following link to reset your password:

{_resetUrl}

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, please ignore this email and your password will remain unchanged.

Best regards,
{branding.SiteName} Team";
    }
}