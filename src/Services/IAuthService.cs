using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public interface IAuthService
{
    Task<IdentityResult> Register(AuthUser user, string password, string? subdomain = null, Guid? tenantId = null, string? returnUrl = null);
    Task<AuthTokenBundle> Login(string email, string password, Guid? tenantId = null, Guid? siteId = null);

    //Task<AuthTokenBundle> ExternalLoginCallback(Guid? tenantId, Guid? siteId = null);
    //Task<bool> LinkProvider(ExternalLoginRequest request, ClaimsPrincipal user);
    //Task<bool> UnlinkProvider(UnlinkProviderRequest request, ClaimsPrincipal user);
    Task<AuthTokenBundle> RefreshToken(Guid userId,string refreshToken);
    
    // Tenant/Site switching methods
    Task<AuthTokenBundle> SwitchTenant(Guid userId, Guid tenantId);
    Task<AuthTokenBundle> SwitchSite(Guid userId, Guid siteId);
    
    // Availability query methods
    Task<IEnumerable<TenantDto>> GetAvailableTenants(Guid userId);
    Task<IEnumerable<SiteDto>> GetAvailableSites(Guid userId, Guid tenantId);
    
    // User permissions and roles query methods
    Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId, Guid? tenantId = null, Guid? siteId = null);
    Task<IEnumerable<RoleDto>> GetUserRolesAsync(Guid userId, Guid? tenantId = null, Guid? siteId = null);
    
    // Email-related methods

    Task<bool> SendEmailConfirmationAsync(string email, string? subdomain = null, Guid? tenantId = null, string? returnUrl = null);
    Task<bool> ConfirmEmailAsync(Guid userId, string token, string? subdomain = null, Guid? tenantId = null);
    Task<bool> SendPasswordResetAsync(string email, string? subdomain = null, Guid? tenantId = null, string? returnUrl = null);
    Task<bool> ResetPasswordAsync(Guid userId, string token, string newPassword, string? subdomain = null, Guid? tenantId = null);
    
    // Invitation-based registration
    Task<IdentityResult> RegisterViaInvitationAsync(RegisterViaInvitationRequest request);
}