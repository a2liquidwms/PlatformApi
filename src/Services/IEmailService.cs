using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IEmailService 
{
    Task<bool> SendEmailConfirmationAsync(string email, string confirmationUrl, string userName, BrandingContext? branding = null);
    Task<bool> SendPasswordResetAsync(string email, string resetUrl, string userName, BrandingContext? branding = null);
    Task<bool> SendWelcomeEmailAsync(string email, string userName, BrandingContext? branding = null);
    Task<bool> SendEmailAsync(string toEmail, string subject, string htmlBody, string? textBody = null, BrandingContext? branding = null);
    Task<bool> SendTenantInvitationEmailAsync(string email, string invitationUrl, string userName, BrandingContext? branding = null);
}