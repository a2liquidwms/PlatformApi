using PlatformApi.Models;

namespace PlatformApi.Emails;

public static class EmailLayout
{
    public static string WrapContent(string title, string content, BrandingContext branding)
    {
        return $"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>{title}</title><style>{GetCommonCss(branding)}</style></head><body><div class=\"container\"><div class=\"logo\">{branding.SiteName}</div>{content}</div></body></html>";
    }

    private static string GetCommonCss(BrandingContext branding)
    {
        return $"body{{font-family:Arial,sans-serif;line-height:1.6;color:#333;margin:0;padding:20px;background-color:#ffffff;}}.container{{max-width:600px;margin:0 auto;}}.logo{{margin-bottom:30px;font-size:18px;font-weight:bold;}}.button{{display:inline-block;padding:12px 24px;background-color:{branding.PrimaryColor};color:white;text-decoration:none;border-radius:4px;font-weight:normal;margin:20px 0;}}";
    }

}