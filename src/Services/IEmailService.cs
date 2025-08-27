using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IEmailService 
{
    Task<bool> SendEmailConfirmationAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null);
    Task<bool> SendPasswordResetAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null);
    Task<bool> SendWelcomeEmailAsync(string email, string userName, Guid? tenantId = null);
    Task<bool> SendEmailAsync(string toEmail, string subject, string htmlBody, string? textBody = null, BrandingContext? branding = null);
    Task<bool> SendInvitationEmailAsync(string email, string token, string userName, RoleScope scope, Guid? tenantId = null, Guid? siteId = null);
}