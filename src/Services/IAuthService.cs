using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public interface IAuthService
{
    Task<IdentityResult> Register(AuthUser user, string password, string? subdomain = null, Guid? tenantId = null);
    Task<AuthTokenBundle> Login(string email, string password, Guid? tenantId = null, Guid? siteId = null);

    //Task<AuthTokenBundle> ExternalLoginCallback(Guid? tenantId, Guid? siteId = null);
    //Task<bool> LinkProvider(ExternalLoginRequest request, ClaimsPrincipal user);
    //Task<bool> UnlinkProvider(UnlinkProviderRequest request, ClaimsPrincipal user);
    Task<AuthTokenBundle> RefreshToken(string userId,string refreshToken);
    
    // Tenant/Site switching methods
    Task<AuthTokenBundle> SwitchTenant(string userId, Guid tenantId);
    Task<AuthTokenBundle> SwitchSite(string userId, Guid siteId);
    
    // Availability query methods
    Task<IEnumerable<TenantDto>> GetAvailableTenants(string userId);
    Task<IEnumerable<SiteDto>> GetAvailableSites(string userId, Guid? tenantId = null);
    
    // Email-related methods

    Task<bool> SendEmailConfirmationAsync(string email, string? subdomain = null, Guid? tenantId = null);
    Task<bool> ConfirmEmailAsync(string userId, string token, string? subdomain = null, Guid? tenantId = null);
    Task<bool> SendPasswordResetAsync(string email, string? subdomain = null, Guid? tenantId = null);
    Task<bool> ResetPasswordAsync(string userId, string token, string newPassword, string? subdomain = null, Guid? tenantId = null);
    
    // Invitation-based registration
    Task<IdentityResult> RegisterViaInvitationAsync(RegisterViaInvitationRequest request);
}