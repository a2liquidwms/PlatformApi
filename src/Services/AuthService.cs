using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Services;
using PlatformApi.Common.Tenant;
using PlatformApi.Controllers;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Models.Messages;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace PlatformApi.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<AuthUser> _userManager;
    private readonly SignInManager<AuthUser> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;
    private readonly PlatformDbContext _context;
    private readonly IUnitOfWork<PlatformDbContext> _uow;
    private readonly TenantHelper _tenantHelper;
    private readonly IUserService _userService;
    private readonly IEmailService _emailService;
    private readonly IBrandingService _brandingService;
    private readonly ISnsService _snsService;
    private readonly string _refreshTokenDays;
    private readonly string _accessTokenMinutes;

    public AuthService(UserManager<AuthUser> userManager, SignInManager<AuthUser> signInManager,
        IConfiguration configuration, ILogger<AuthService> logger, PlatformDbContext context,
        IUnitOfWork<PlatformDbContext> uow, TenantHelper tenantHelper, 
        IUserService userService, IEmailService emailService, IBrandingService brandingService, ISnsService snsService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _logger = logger;
        _context = context;
        _uow = uow;
        _tenantHelper = tenantHelper;
        _userService = userService;
        _emailService = emailService;
        _brandingService = brandingService;
        _snsService = snsService;
        _refreshTokenDays = configuration["AUTH_REFRESH_TOKEN_DAYS"] ?? "5";
        _accessTokenMinutes = configuration["AUTH_ACCESS_TOKEN_MINUTES"] ?? "5";
    }

    // Overload for Register with branding context
    public async Task<IdentityResult> Register(AuthUser user, string password, string? subdomain = null, Guid? tenantId = null)
    {
        var result = await _userManager.CreateAsync(user, password);
        
        if (result.Succeeded)
        {
            // Send email confirmation with branding context
            await SendEmailConfirmationAsync(user.Email!, subdomain, tenantId);
            
            // Publish user-created message
            var userCreatedMessage = new UserCreatedMessage
            {
                UserId = user.Id.ToString(),
                Email = user.Email!
            };
            await _snsService.PublishUserCreatedAsync(userCreatedMessage);
        }

        return result;
    }

    public async Task<AuthTokenBundle> Login(string email, string password, Guid? tenantId = null, Guid? siteId = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
            throw new InvalidDataException("Invalid login");

        // Check if email is confirmed
        if (!user.EmailConfirmed)
            throw new InvalidDataException("Email not confirmed. Please check your email for the confirmation link.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
        if (!result.Succeeded)
            throw new InvalidDataException("Invalid login");

        if (tenantId != null)
        {
            await ValidateUserTenantAccess(user, (Guid)tenantId);
        }

        if (siteId != null && tenantId == null)
        {
            throw new InvalidDataException("Cannot login to site without specifying tenant");
        }

        if (siteId != null)
        {
            await ValidateUserSiteAccess(user, (Guid)siteId, (Guid)tenantId!);
        }

        var token = await GenerateTokenBundle(user, tenantId, siteId);

        return token;
    }

    private async Task ValidateUserTenantAccess(AuthUser user, Guid tenantId)
    {
        // Check for tenant membership using UserService
        var hasAccess = await _userService.HasTenantAccess(user.Id, tenantId);
        
        if (!hasAccess)
        {
            throw new InvalidDataException("Tenant access denied");
        }
    }

    private async Task ValidateUserSiteAccess(AuthUser user, Guid siteId, Guid tenantId)
    {
        var hasAccess = await _userService.HasSiteAccess(user.Id, siteId, tenantId);
        
        if (!hasAccess)
        {
            throw new InvalidDataException("Site Access denied");
        }
    }

    // public async Task<AuthTokenBundle> ExternalLoginCallback(Guid? tenantId, Guid? siteId = null)
    // {
    //     var info = await _signInManager.GetExternalLoginInfoAsync();
    //     if (info == null)
    //     {
    //         throw new InvalidOperationException("Invalid login provider");
    //     }
    //
    //     var email = info.Principal.FindFirstValue(ClaimTypes.Email);
    //
    //     if (email == null)
    //     {
    //         throw new InvalidOperationException("Invalid email");
    //     }
    //
    //     var user = await GetUserByEmail(email);
    //
    //     if (user == null)
    //     {
    //         // Create new user if none exists
    //         user = new AuthUser
    //         {
    //             UserName = email, // Using email as username is more reliable
    //             Email = email,
    //             EmailConfirmed = true // Since it's verified by Google
    //         };
    //
    //         var createResult = await _userManager.CreateAsync(user);
    //         if (!createResult.Succeeded)
    //         {
    //             _logger.LogError("Error Creating User Provider");
    //             _logger.LogError(createResult.Errors.ToString());
    //             throw new SystemException("Issue Creating User");
    //         }
    //
    //         // Get branding context and send welcome email for external login users
    //         var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
    //         await _emailService.SendWelcomeEmailAsync(user.Email!, user.UserName ?? user.Email!, branding);
    //         
    //         // Publish user-created message for external login users
    //         var userCreatedMessage = new UserCreatedMessage
    //         {
    //             UserId = user.Id.ToString(),
    //             Email = user.Email!
    //         };
    //         await _snsService.PublishUserCreatedAsync(userCreatedMessage);
    //     }
    //
    //     // Add the external login provider to the user if it's not already there
    //     if (await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey) == null)
    //     {
    //         var addLoginResult = await _userManager.AddLoginAsync(user, info);
    //         if (!addLoginResult.Succeeded)
    //         {
    //             _logger.LogError("Error Creating User Provider");
    //             throw new SystemException("Issue Adding Provider");
    //         }
    //     }
    //
    //     // Validate site access if provided
    //     if (siteId != null && tenantId == null)
    //     {
    //         throw new InvalidDataException("Cannot login to site without specifying tenant");
    //     }
    //
    //     if (siteId != null)
    //     {
    //         await ValidateUserSiteAccess(user, (Guid)siteId, (Guid)tenantId!);
    //     }
    //
    //     // Generate tokens
    //     return await GenerateTokenBundle(user, tenantId, siteId);
    // }

    // public async Task<bool> LinkProvider(ExternalLoginRequest request, ClaimsPrincipal user)
    // {
    //     var validUser = await _userManager.GetUserAsync(user);
    //     if (user == null) throw new UnauthorizedAccessException();
    //
    //     var loginInfo = new UserLoginInfo(request.Provider, request.ProviderKey, request.Provider);
    //     var result = await _userManager.AddLoginAsync(validUser!, loginInfo);
    //
    //     if (!result.Succeeded) throw new SystemException(result.Errors.ToString());
    //     return true;
    // }

    // public async Task<bool> UnlinkProvider(UnlinkProviderRequest request, ClaimsPrincipal user)
    // {
    //     var validUser = await _userManager.GetUserAsync(user);
    //     if (user == null) throw new UnauthorizedAccessException();
    //
    //     var result = await _userManager.RemoveLoginAsync(validUser!, request.Provider, request.ProviderKey);
    //
    //     if (!result.Succeeded) throw new SystemException(result.Errors.ToString());
    //     return true;
    // }

    public async Task<AuthTokenBundle> RefreshToken(string userId, string refreshToken)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null || user.Id.ToString() != userId)
        {
            _logger.LogError("User Not Match Refresh Token");
            throw new UnauthorizedAccessException();
        }
        
        var oldRefreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken.Trim() && rt.UserId == Guid.Parse(userId));
        
        if (oldRefreshToken == null || oldRefreshToken.IsRevoked || oldRefreshToken.Expires < DateTime.UtcNow)
        {
            _logger.LogError("Refresh Token not found or Expired");
            throw new UnauthorizedAccessException();
        }
        
        //revoke all other refresh tokens
        var otherRefreshToken = _context.RefreshTokens.Where(rt => rt.UserId == Guid.Parse(userId) && !rt.IsRevoked);

        foreach (var token in otherRefreshToken)
        {
            token.IsRevoked = true;
        }

        // Generate new access and refresh tokens
        var tokenBundle = await GenerateTokenBundle(user, oldRefreshToken.TenantId, oldRefreshToken.SiteId);

        return tokenBundle;
    }

    // EMAIL METHODS WITH BRANDING SUPPORT

    public async Task<bool> SendEmailConfirmationAsync(string email, string? subdomain = null, Guid? tenantId = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning("Attempted to send confirmation email to non-existent user: {Email}", email);
            return true; // Don't reveal that the user doesn't exist
        }

        if (user.EmailConfirmed)
        {
            _logger.LogInformation("Email already confirmed for user: {Email}", email);
            return true; // Already confirmed
        }

        // Get branding context
        var branding = await _brandingService.GetBrandingContextAsync(subdomain, tenantId);

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = HttpUtility.UrlEncode(token);
        var encodedUserId = HttpUtility.UrlEncode(user.Id.ToString());
        
        // Use the branding context to build the confirmation URL
        var confirmationUrl = $"{branding.BaseUrl}/confirm-email?token={encodedToken}&userId={encodedUserId}";

        return await _emailService.SendEmailConfirmationAsync(user.Email!, confirmationUrl, user.UserName ?? user.Email!, branding);
    }

    public async Task<bool> ConfirmEmailAsync(string userId, string token, string? subdomain = null, Guid? tenantId = null)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("Attempted to confirm email for non-existent user: {UserId}", userId);
            return false;
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Email confirmed successfully for user: {UserId}", userId);
            
            var branding = await _brandingService.GetBrandingContextAsync(subdomain, tenantId);
            
            // Send welcome email after successful confirmation
            await _emailService.SendWelcomeEmailAsync(user.Email!, user.UserName ?? user.Email!, branding);
            
            return true;
        }

        _logger.LogWarning("Failed to confirm email for user: {UserId}. Errors: {Errors}", 
            userId, string.Join(", ", result.Errors.Select(e => e.Description)));
        
        return false;
    }

    public async Task<bool> SendPasswordResetAsync(string email, string? subdomain = null, Guid? tenantId = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || !user.EmailConfirmed)
        {
            _logger.LogWarning("Attempted to send password reset to non-existent or unconfirmed user: {Email}", email);
            return true; // Don't reveal that the user doesn't exist or is unconfirmed
        }

        // Get branding context
        var branding = await _brandingService.GetBrandingContextAsync(subdomain, tenantId);

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var encodedToken = HttpUtility.UrlEncode(token);
        var encodedUserId = HttpUtility.UrlEncode(user.Id.ToString());
        
        // Use the branding context to build the reset URL
        var resetUrl = $"{branding.BaseUrl}/reset-password?token={encodedToken}&userId={encodedUserId}";

        return await _emailService.SendPasswordResetAsync(user.Email!, resetUrl, user.UserName ?? user.Email!, branding);
    }

    public async Task<bool> ResetPasswordAsync(string userId, string token, string newPassword, string? subdomain = null, Guid? tenantId = null)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("Attempted to reset password for non-existent user: {UserId}", userId);
            return false;
        }

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Password reset successfully for user: {UserId}", userId);
            return true;
        }

        _logger.LogWarning("Failed to reset password for user: {UserId}. Errors: {Errors}", 
            userId, string.Join(", ", result.Errors.Select(e => e.Description)));
        
        return false;
    }

    // EXISTING METHODS (unchanged)

    private async Task<AuthTokenBundle> GenerateTokenBundle(AuthUser user, Guid? tenantId = null, Guid? siteId = null)
    {
        var tokenReturn = await GenerateJwtToken(user, tenantId, siteId);
        var refreshToken = await GenerateRefreshToken(user, tenantId, siteId);

        return new AuthTokenBundle()
        {
            AccessToken = tokenReturn.AccessToken,
            TokenType = "Bearer",
            RefreshToken = refreshToken,
            Expires = (int)new DateTimeOffset(tokenReturn.Expires).ToUnixTimeSeconds(),
            TenantId = tenantId,
            SiteId = siteId
        };
    }

    private async Task<JwtTokenReturn> GenerateJwtToken(AuthUser user, Guid? tenantId = null, Guid? siteId = null)
    {
        var issuer = _configuration["JWT_ISSUER"] ?? throw new InvalidOperationException("JWT_ISSUER is missing");
        var audience = _configuration["JWT_AUDIENCE"] ?? throw new InvalidOperationException("JWT_AUDIENCE is missing");
        var secretKey = _configuration["JWT_SECRET"] ?? throw new InvalidOperationException("JWT_SECRET is missing");
        var expiresEpoch = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_accessTokenMinutes));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = await GetAllClaims(user, tenantId, siteId);

        var newToken = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: expiresEpoch,
            signingCredentials: creds
        );

        var tokenHandler = new JwtSecurityTokenHandler();

        return new JwtTokenReturn
        {
            AccessToken = tokenHandler.WriteToken(newToken),
            Expires = expiresEpoch
        };
    }

    private async Task<List<Claim>> GetAllClaims(AuthUser user, Guid? tenantId = null, Guid? siteId = null)
    {
        var allClaims = new List<Claim>();
        
        // Standard JWT claims
        var defaultClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(CommonConstants.ClaimUserId, user.Id.ToString())
        };
        allClaims.AddRange(defaultClaims);

        // Add context claims (tenant/site)
        if (tenantId.HasValue)
        {
            allClaims.Add(new Claim(CommonConstants.ActiveTenantClaim, tenantId.Value.ToString()));
        }
        
        if (siteId.HasValue)
        {
            allClaims.Add(new Claim(CommonConstants.ActiveSiteClaim, siteId.Value.ToString()));
        }

        // Get role claims based on context
        var roleClaims = await GetContextualRoleClaims(user, tenantId, siteId);
        allClaims.AddRange(roleClaims);

        return allClaims;
    }

    private async Task<List<Claim>> GetContextualRoleClaims(AuthUser user, Guid? tenantId, Guid? siteId)
    {
        var allRoles = new List<Role>();
        
        // Always get Internal and Default roles
        var defaultRoles = await _userService.GetUserRoles(user.Id, RoleScope.Default);
        var internalRoles = await _userService.GetUserRoles(user.Id, RoleScope.Internal);
        
        allRoles.AddRange(defaultRoles);
        allRoles.AddRange(internalRoles);
        
        // Add tenant roles if tenant context exists
        if (tenantId.HasValue)
        {
            var tenantRoles = await _userService.GetUserRoles(user.Id, RoleScope.Tenant, tenantId);
            allRoles.AddRange(tenantRoles);
        }
        
        // Add site roles if site context exists
        if (siteId.HasValue && tenantId.HasValue)
        {
            var siteRoles = await _userService.GetUserRoles(user.Id, RoleScope.Site, tenantId, siteId);
            allRoles.AddRange(siteRoles);
        }
        
        // Create role claims
        var roleClaims = new List<Claim>();
        var allRoleNames = allRoles.Select(r => r.Name).Distinct().ToArray();
        var roleJsonArray = JsonSerializer.Serialize(allRoleNames);
        roleClaims.Add(new Claim(CommonConstants.RolesClaim, roleJsonArray, JsonClaimValueTypes.JsonArray));
        
        // Add admin roles claim for system roles
        var adminRoles = allRoles.Where(r => r.IsSystemRole).ToList();
        if (adminRoles.Any())
        {
            var adminRoleNames = adminRoles.Select(r => r.Name).ToArray();
            var adminJsonArray = JsonSerializer.Serialize(adminRoleNames);
            roleClaims.Add(new Claim(CommonConstants.AdminRolesClaim, adminJsonArray, JsonClaimValueTypes.JsonArray));
        }

        return roleClaims;
    }

    private async Task<string> GenerateRefreshToken(AuthUser user, Guid? tenantId = null, Guid? siteId = null)
    {
        var randomBytes = RandomNumberGenerator.GetBytes(64);
        var urlSafeToken = Convert.ToBase64String(randomBytes)
            .Replace('+', '-')    // Replace URL-unsafe characters
            .Replace('/', '_')    // Replace URL-unsafe characters
            .Replace("=", "");    // Remove padding characters
        
        var refreshToken = new RefreshToken
        {
            Token = urlSafeToken,
            UserId = user.Id,
            Expires = DateTime.UtcNow.AddDays(Convert.ToDouble(_refreshTokenDays)),
            IsRevoked = false,
            TenantId = tenantId,
            SiteId = siteId
        };

        _context.RefreshTokens.Add(refreshToken);
        await _uow.CompleteAsync();

        return refreshToken.Token;
    }

    public async Task<AuthTokenBundle> SwitchTenant(string userId, Guid tenantId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new NotFoundException("User not found");
        }

        // Validate user has access to this tenant using UserService
        var hasAccess = await _userService.HasTenantAccess(user.Id, tenantId);
        
        if (!hasAccess)
        {
            throw new InvalidDataException("User is not assigned to this tenant");
        }

        // Revoke all existing refresh tokens for this user
        var existingTokens = _context.RefreshTokens.Where(rt => rt.UserId == user.Id && !rt.IsRevoked);
        foreach (var token in existingTokens)
        {
            token.IsRevoked = true;
        }

        // Generate new token bundle with tenant context (no site)
        var tokenBundle = await GenerateTokenBundle(user, tenantId, null);
        
        return tokenBundle;
    }

    public async Task<AuthTokenBundle> SwitchSite(string userId, Guid siteId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new NotFoundException("User not found");
        }

        // Get site info to validate tenant
        var site = await _context.Sites
            .FirstOrDefaultAsync(s => s.Id == siteId && s.IsActive);
        
        if (site == null)
        {
            throw new NotFoundException("Site not found or inactive");
        }

        // Validate user has access to this site
        await ValidateUserSiteAccess(user, siteId, site.TenantId);

        // Revoke all existing refresh tokens for this user
        var existingTokens = _context.RefreshTokens.Where(rt => rt.UserId == user.Id && !rt.IsRevoked);
        foreach (var token in existingTokens)
        {
            token.IsRevoked = true;
        }

        // Generate new token bundle with site context (includes tenant)
        var tokenBundle = await GenerateTokenBundle(user, site.TenantId, siteId);
        
        return tokenBundle;
    }

    public async Task<IEnumerable<TenantDto>> GetAvailableTenants(string userId)
    {
        var userGuid = Guid.Parse(userId);
        return await _userService.GetUserTenants(userGuid);
    }

    public async Task<IEnumerable<SiteDto>> GetAvailableSites(string userId, Guid? tenantId = null)
    {
        var userGuid = Guid.Parse(userId);
        return await _userService.GetUserSites(userGuid, tenantId);
    }
    
    // TODO: Refactor this method to not depend on IOldUserService
    public async Task<IdentityResult> RegisterViaInvitationAsync(RegisterViaInvitationRequest request)
    {
        // This method needs to be refactored to use IUserService instead of IOldUserService
        await Task.CompletedTask; // Remove this when implementing
        throw new NotImplementedException("RegisterViaInvitationAsync needs to be refactored to use new user service");
    }
}

public class JwtTokenReturn
{
    public required string AccessToken { get; set; }
    public required DateTime Expires { get; set; }
}