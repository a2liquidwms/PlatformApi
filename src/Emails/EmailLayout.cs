using PlatformApi.Models;

namespace PlatformApi.Emails;

public static class EmailLayout
{
    public static string WrapContent(string title, string content, BrandingContext branding)
    {
        return
            $"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>{title}</title><style>{GetCommonCss(branding)}</style></head><body><div class=\"container\">{GetHeader(title, branding)}<div class=\"content\">{content}</div>{GetFooter(branding)}</div></body></html>";
    }

    private static string GetCommonCss(BrandingContext branding)
    {
        return
            $"body{{font-family:Arial,sans-serif;line-height:1.6;color:#333;margin:0;padding:0;background-color:#ffffff;}}.container{{max-width:600px;margin:0 auto;background-color:white;box-shadow:0 0 10px rgba(0,0,0,0.1);}}.header{{background-color:{branding.PrimaryColor};color:white;padding:20px;text-align:center;}}.header h1{{margin:0;font-size:24px;}}.logo{{max-height:50px;margin-bottom:10px;}}.content{{padding:30px;background-color:#f9f9f9;}}.content h2{{color:#333;margin-top:0;}}.button{{display:inline-block;padding:12px 30px;background-color:{branding.PrimaryColor};color:white;text-decoration:none;border-radius:5px;font-weight:bold;}}.button:hover{{opacity:0.9;}}.footer{{padding:20px;text-align:center;font-size:12px;color:#666;background-color:#f0f0f0;}}.warning{{background-color:#fff3cd;border:1px solid #ffeaa7;padding:15px;border-radius:5px;margin:20px 0;}}.url-box{{word-break:break-all;background-color:#f0f0f0;padding:10px;border-radius:3px;margin:10px 0;border:1px solid #ddd;}}.center{{text-align:center;margin:30px 0;}}";
    }

    private static string GetHeader(string title, BrandingContext branding)
    {
        var logoHtml = string.IsNullOrEmpty(branding.LogoPath)
            ? ""
            : $"<img src=\"{branding.LogoPath}\" alt=\"{branding.SiteName}\" class=\"logo\" />";

        return $"<div class=\"header\">{logoHtml}<h1>{title}</h1></div>";
    }

    private static string GetFooter(BrandingContext branding)
    {
        return $"<div class=\"footer\"><p>&copy; {DateTime.UtcNow.Year} {branding.SiteName}</p></div>";
    }
}