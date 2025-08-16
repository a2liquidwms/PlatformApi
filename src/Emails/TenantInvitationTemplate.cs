using PlatformApi.Models;

namespace PlatformApi.Emails;

public class TenantInvitationTemplate : EmailTemplateBase
{
    private readonly string _userName;
    private readonly string _invitationUrl;

    public TenantInvitationTemplate(string userName, string invitationUrl)
    {
        _userName = userName;
        _invitationUrl = invitationUrl;
    }

    public override string GetSubject(BrandingContext branding)
    {
        return $"You're Invited to Join {branding.SiteName}";
    }

    protected override string GetEmailTitle()
    {
        return "You're Invited!";
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<h2>Hello {_userName}!</h2><p>You've been invited to join <strong>{branding.SiteName}</strong>.</p><p>To complete your registration and set up your account, please click the button below:</p><div class=\"center\"><a href=\"{_invitationUrl}\" class=\"button\">Accept Invitation & Register</a></div><p>If the button doesn't work, you can copy and paste this link into your browser:</p><div class=\"url-box\">{_invitationUrl}</div><div class=\"warning\"><strong>Important:</strong> This invitation will expire in 7 days for security reasons.</div><p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p><p>Welcome to {branding.SiteName}!</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"You're Invited to Join {branding.SiteName}!

Hello {_userName}!

You've been invited to join {branding.SiteName}. 

To complete your registration and set up your account, please visit:
{_invitationUrl}

Important: This invitation will expire in 7 days for security reasons.

If you have any questions or need assistance, please don't hesitate to contact our support team.

Welcome to {branding.SiteName}!

Best regards,
{branding.SiteName} Team

This email was sent to {_userName}. If you didn't expect this invitation, you can safely ignore this email.";
    }
}