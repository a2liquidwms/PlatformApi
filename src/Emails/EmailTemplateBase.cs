using PlatformApi.Models;

namespace PlatformApi.Emails;

public abstract class EmailTemplateBase : IEmailTemplate
{
    public virtual string GenerateHtml(BrandingContext branding)
    {
        var title = GetEmailTitle();
        var content = GetHtmlContent(branding);
        return EmailLayout.WrapContent(title, content, branding);
    }

    public abstract string GenerateText(BrandingContext branding);
    public abstract string GetSubject(BrandingContext branding);
    
    protected abstract string GetEmailTitle();
    protected abstract string GetHtmlContent(BrandingContext branding);
}