using PlatformApi.Models;

namespace PlatformApi.Emails;

public class SiteInvitationTemplate : EmailTemplateBase
{
    private readonly string _userName;
    private readonly string _invitationUrl;
    private readonly string _siteName;

    public SiteInvitationTemplate(string userName, string invitationUrl, string siteName)
    {
        _userName = userName;
        _invitationUrl = invitationUrl;
        _siteName = siteName;
    }

    public override string GetSubject(BrandingContext branding)
    {
        return $"You're Invited to Join {_siteName} on {branding.SiteName}";
    }

    protected override string GetEmailTitle(BrandingContext branding)
    {
        return branding.SiteName;
    }

    protected override string GetHtmlContent(BrandingContext branding)
    {
        return $"<p>Hi {_userName},</p><p>You've been invited to join the {_siteName} site on {branding.SiteName}.</p><a href=\"{_invitationUrl}\" class=\"button\">Accept Invitation</a><p>This invitation expires in 7 days.</p><p>If you didn't expect this invitation, please ignore this email.</p><p>Your {branding.SiteName} Team</p>";
    }

    public override string GenerateText(BrandingContext branding)
    {
        return $@"Hi {_userName},

You've been invited to join the {_siteName} site on {branding.SiteName}.

{_invitationUrl}

This invitation expires in 7 days.

If you didn't expect this invitation, please ignore this email.

Your {branding.SiteName} Team";
    }
}