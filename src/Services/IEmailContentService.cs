using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IEmailContentService
{
    Task<EmailContent> PrepareEmailConfirmationAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null);
    Task<EmailContent> PreparePasswordResetAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null);
    Task<EmailContent> PrepareWelcomeEmailAsync(string email, string userName, Guid? tenantId = null);
    Task<EmailContent> PrepareInvitationEmailAsync(string email, string token, string userName, RoleScope scope, Guid? tenantId = null, Guid? siteId = null);
}