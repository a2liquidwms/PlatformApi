using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;

namespace PlatformApi.Services;

public interface IAuthService
{
    Task<IdentityResult> Register(AuthUser user, string password, string? subdomain = null, Guid? tenantId = null);
    Task<AuthTokenBundle> Login(string email, string password, Guid? tenantId);
    Task<AuthUser?> GetUserByEmail(string email);
    Task<AuthTokenBundle> ExternalLoginCallback(Guid? tenantId);
    Task<bool> LinkProvider(ExternalLoginRequest request, ClaimsPrincipal user);
    Task<bool> UnlinkProvider(UnlinkProviderRequest request, ClaimsPrincipal user);
    Task<AuthTokenBundle> RefreshToken(string userId,string refreshToken);
    
    // Email-related methods

    Task<bool> SendEmailConfirmationAsync(string email, string? subdomain = null, Guid? tenantId = null);
    Task<bool> ConfirmEmailAsync(string userId, string token, string? subdomain = null, Guid? tenantId = null);
    Task<bool> SendPasswordResetAsync(string email, string? subdomain = null, Guid? tenantId = null);
    Task<bool> ResetPasswordAsync(string userId, string token, string newPassword, string? subdomain = null, Guid? tenantId = null);
    
    // Invitation-based registration
    Task<IdentityResult> RegisterViaInvitationAsync(RegisterViaInvitationRequest request);
}