using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Services;
using PlatformApi.Common.Tenant;
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
    private readonly ITenantService _tenantService;
    private readonly IEmailContentService _emailContentService;
    private readonly IEmailService _emailService;
    private readonly ISnsService _snsService;
    private readonly string _refreshTokenDays;
    private readonly string _accessTokenMinutes;

    public AuthService(UserManager<AuthUser> userManager, SignInManager<AuthUser> signInManager,
        IConfiguration configuration, ILogger<AuthService> logger, PlatformDbContext context,
        IUnitOfWork<PlatformDbContext> uow, TenantHelper tenantHelper, 
        IUserService userService, ITenantService tenantService, IEmailContentService emailContentService, IEmailService emailService, ISnsService snsService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _logger = logger;
        _context = context;
        _uow = uow;
        _tenantHelper = tenantHelper;
        _userService = userService;
        _tenantService = tenantService;
        _emailContentService = emailContentService;
        _emailService = emailService;
        _snsService = snsService;
        _refreshTokenDays = configuration["AUTH_REFRESH_TOKEN_DAYS"] ?? "180";
        _accessTokenMinutes = configuration["AUTH_ACCESS_TOKEN_MINUTES"] ?? "5";
    }

    // Overload for Register with branding context
    public async Task<IdentityResult> Register(AuthUser user, string password, string? subdomain = null, Guid? tenantId = null, string? returnUrl = null)
    {
        var result = await _userManager.CreateAsync(user, password);
        
        if (result.Succeeded)
        {
            // Send email confirmation with branding context
            await SendEmailConfirmationAsync(user.Email!, subdomain, tenantId, returnUrl);
            
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

    public async Task<AuthTokenBundleWithRefresh> Login(string email, string password, Guid? tenantId = null, Guid? siteId = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning("Login attempt failed - user not found for email: {Email}", email);
            throw new InvalidDataException("Invalid login");
        }

        // Check if email is confirmed
        if (!user.EmailConfirmed)
        {
            _logger.LogWarning("Login attempt failed - email not confirmed for user: {UserId} ({Email})", user.Id, email);
            throw new InvalidDataException("Email not confirmed. Please check your email for the confirmation link.");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Login attempt failed - invalid password for user: {UserId} ({Email})", user.Id, email);
            throw new InvalidDataException("Invalid login");
        }

        if (tenantId != null)
        {
            await ValidateUserTenantAccess(user, (Guid)tenantId);
        }

        if (siteId != null && tenantId == null)
        {
            _logger.LogWarning("Login attempt failed - site specified without tenant for user: {UserId} ({Email})", user.Id, email);
            throw new InvalidDataException("Cannot login to site without specifying tenant");
        }

        if (siteId != null)
        {
            await ValidateUserSiteAccess(user, (Guid)siteId, (Guid)tenantId!);
        }
        
        var token = await GenerateTokenBundle(user, tenantId, siteId);
        
        _logger.LogInformation("User {UserId} ({Email}) logged in successfully with tenant {TenantId} and site {SiteId}", 
            user.Id, email, tenantId, siteId);

        return token;
    }

    private async Task<(Guid? tenantId, Guid? siteId)> AutoSelectTenantAndSite(AuthUser user, Guid? inputTenantId = null, Guid? inputSiteId = null)
    {
        var tenantId = inputTenantId;
        var siteId = inputSiteId;
        
        // Auto-select tenant if not specified
        if (tenantId == null)
        {
            var userTenants = await _userService.GetUserTenants(user.Id, forLogin: true);
            var tenantList = userTenants.ToList();
            
            // If user has exactly one tenant, auto-select it
            if (tenantList.Count == 1)
            {
                tenantId = tenantList[0].Id;
            }
        }
        
        // If we have a tenant and no site specified, check for auto-select site
        if (tenantId != null && siteId == null)
        {
            var userSites = await _userService.GetUserSites(user.Id, tenantId.Value, forLogin: true);
            var siteList = userSites.ToList();
            
            // If user has exactly one site in this tenant, auto-select it
            if (siteList.Count == 1)
            {
                siteId = siteList[0].Id;
            }
        }
        
        return (tenantId, siteId);
    }

    private async Task ValidateUserTenantAccess(AuthUser user, Guid tenantId)
    {
        // Check for tenant membership using UserService with forLogin=true to bypass permission middleware
        var hasAccess = await _userService.HasTenantAccess(user.Id, tenantId, forLogin: true);
        
        if (!hasAccess)
        {
            _logger.LogWarning("Tenant access denied for user {UserId} ({Email}) to tenant {TenantId}", 
                user.Id, user.Email, tenantId);
            throw new InvalidDataException("Tenant access denied");
        }
    }

    private async Task ValidateUserSiteAccess(AuthUser user, Guid siteId, Guid tenantId)
    {
        // Check for site membership using UserService with forLogin=true to bypass permission middleware
        var hasAccess = await _userService.HasSiteAccess(user.Id, siteId, tenantId, forLogin: true);
        
        if (!hasAccess)
        {
            _logger.LogWarning("Site access denied for user {UserId} ({Email}) to site {SiteId} in tenant {TenantId}", 
                user.Id, user.Email, siteId, tenantId);
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

    public async Task<AuthTokenBundleWithRefresh> RefreshToken(string refreshToken)
    {
        // Find the refresh token first to get the userId - more secure approach
        var oldRefreshToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken.Trim() && !rt.IsRevoked);
        
        if (oldRefreshToken == null)
        {
            _logger.LogWarning("Refresh token not found or already revoked");
            throw new UnauthorizedAccessException();
        }
        
        if (oldRefreshToken.Expires < DateTime.UtcNow)
        {
            _logger.LogWarning("Refresh token expired for user {UserId}", oldRefreshToken.UserId);
            throw new UnauthorizedAccessException();
        }
        
        // Now get the user from the refresh token
        var user = await _userManager.FindByIdAsync(oldRefreshToken.UserId.ToString());
        if (user == null)
        {
            _logger.LogWarning("User {UserId} not found for refresh token", oldRefreshToken.UserId);
            throw new UnauthorizedAccessException();
        }
        
        //revoke all other refresh tokens for this user
        var otherRefreshToken = _context.RefreshTokens.Where(rt => rt.UserId == oldRefreshToken.UserId && !rt.IsRevoked);

        foreach (var token in otherRefreshToken)
        {
            token.IsRevoked = true;
        }

        // Generate new access and refresh tokens
        var tokenBundle = await GenerateTokenBundle(user, oldRefreshToken.TenantId, oldRefreshToken.SiteId);
        
        _logger.LogDebug("Token refreshed successfully for user {UserId} ({Email}) with tenant {TenantId} and site {SiteId}", 
            user.Id, user.Email, oldRefreshToken.TenantId, oldRefreshToken.SiteId);

        return tokenBundle;
    }

    public async Task<bool> Logout(Guid userId)
    {
        try
        {
            // Revoke ALL refresh tokens for this user (logout from all devices)
            var userRefreshTokens = _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked);

            foreach (var token in userRefreshTokens)
            {
                token.IsRevoked = true;
            }

            await _uow.CompleteAsync();
            _logger.LogInformation("User {UserId} logged out - all refresh tokens revoked", userId);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout for user {UserId}", userId);
            return false;
        }
    }
    
    public async Task<bool> SendEmailConfirmationAsync(string email, string? subdomain = null, Guid? tenantId = null, string? returnUrl = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning("Attempted to send confirmation email to non-existent user: {Email}", email);
            return true; // Don't reveal that the user doesn't exist
        }

        if (user.EmailConfirmed)
        {
            _logger.LogInformation("Email already confirmed for user: {UserId} ({Email})", user.Id, email);
            return true; // Already confirmed
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var emailContent = await _emailContentService.PrepareEmailConfirmationAsync(user.Email!, token, user.Id, user.UserName ?? user.Email!, tenantId, returnUrl);
        var emailSent = await _emailService.SendEmailAsync(emailContent);
        
        if (emailSent)
        {
            _logger.LogInformation("Email confirmation sent successfully to user {UserId} ({Email}) with tenant {TenantId}", 
                user.Id, email, tenantId);
        }
        else
        {
            _logger.LogError("Failed to send email confirmation to user {UserId} ({Email}) with tenant {TenantId}", 
                user.Id, email, tenantId);
        }
        
        return emailSent;
    }

    public async Task<bool> ConfirmEmailAsync(Guid userId, string token, string? subdomain = null, Guid? tenantId = null)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            _logger.LogWarning("Attempted to confirm email for non-existent user: {UserId}", userId);
            return false;
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        
        if (result.Succeeded)
        {
            _logger.LogInformation("Email confirmed successfully for user: {UserId}", userId);
            
            // Send welcome email after successful confirmation
            var welcomeEmailContent = await _emailContentService.PrepareWelcomeEmailAsync(user.Email!, user.UserName ?? user.Email!, tenantId);
            await _emailService.SendEmailAsync(welcomeEmailContent);
            
            return true;
        }

        _logger.LogWarning("Failed to confirm email for user: {UserId}. Errors: {Errors}", 
            userId, string.Join(", ", result.Errors.Select(e => e.Description)));
        
        return false;
    }

    public async Task<bool> SendPasswordResetAsync(string email, string? subdomain = null, Guid? tenantId = null, string? returnUrl = null)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null || !user.EmailConfirmed)
        {
            _logger.LogWarning("Attempted to send password reset to non-existent or unconfirmed user: {Email}", email);
            return true; // Don't reveal that the user doesn't exist or is unconfirmed
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var emailContent = await _emailContentService.PreparePasswordResetAsync(user.Email!, token, user.Id, user.UserName ?? user.Email!, tenantId, returnUrl);
        var emailSent = await _emailService.SendEmailAsync(emailContent);
        
        if (emailSent)
        {
            _logger.LogInformation("Password reset email sent successfully to user {UserId} ({Email}) with tenant {TenantId}", 
                user.Id, email, tenantId);
        }
        else
        {
            _logger.LogError("Failed to send password reset email to user {UserId} ({Email}) with tenant {TenantId}", 
                user.Id, email, tenantId);
        }
        
        return emailSent;
    }

    public async Task<bool> ResetPasswordAsync(Guid userId, string token, string newPassword, string? subdomain = null, Guid? tenantId = null)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
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

    private async Task<AuthTokenBundleWithRefresh> GenerateTokenBundle(AuthUser user, Guid? tenantId = null, Guid? siteId = null)
    {
        // Auto-select tenant/site if not specified
        (tenantId, siteId) = await AutoSelectTenantAndSite(user, tenantId, siteId);
        
        var tokenReturn = await GenerateJwtToken(user, tenantId, siteId);
        var refreshToken = await GenerateRefreshToken(user, tenantId, siteId);
        
        // Lookup tenant subdomain if tenantId is provided
        string? tenantSubdomain = null;
        if (tenantId.HasValue)
        {
            var tenant = await _tenantService.GetById(tenantId.Value);
            tenantSubdomain = tenant?.SubDomain;
        }

        _logger.LogInformation("Token bundle generated for user {UserId} ({Email}) with tenant {TenantId}, site {SiteId}, expires at {ExpiresAt}", 
            user.Id, user.Email, tenantId, siteId, tokenReturn.Expires);

        return new AuthTokenBundleWithRefresh()
        {
            AccessToken = tokenReturn.AccessToken,
            TokenType = "Bearer",
            RefreshToken = refreshToken,
            Expires = (int)new DateTimeOffset(tokenReturn.Expires).ToUnixTimeSeconds(),
            TenantId = tenantId,
            SiteId = siteId,
            TenantSubdomain = tenantSubdomain
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
        _logger.LogDebug("Added standard JWT claims for user {UserId}: Sub, Email, Jti, UserId", user.Id);

        // Add tenant count claim for UI decision-making
        var tenantCount = await _userService.GetUserTenantCount(user.Id);
        allClaims.Add(new Claim(CommonConstants.TenantCountClaim, tenantCount.ToString()));
        _logger.LogDebug("Added tenant count claim for user {UserId}: {TenantCount}", user.Id, tenantCount);
        
        // Add context claims (tenant/site)
        if (tenantId.HasValue)
        {
            allClaims.Add(new Claim(CommonConstants.ActiveTenantClaim, tenantId.Value.ToString()));
            _logger.LogDebug("Added active tenant claim for user {UserId}: {TenantId}", user.Id, tenantId.Value);
            
            // Add site count for this tenant
            var siteCount = await _userService.GetUserSiteCount(user.Id, tenantId.Value);
            allClaims.Add(new Claim(CommonConstants.SiteCountClaim, siteCount.ToString()));
            _logger.LogDebug("Added site count claim for user {UserId} in tenant {TenantId}: {SiteCount}", 
                user.Id, tenantId.Value, siteCount);
        }
        
        if (siteId.HasValue)
        {
            allClaims.Add(new Claim(CommonConstants.ActiveSiteClaim, siteId.Value.ToString()));
            _logger.LogDebug("Added active site claim for user {UserId}: {SiteId}", user.Id, siteId.Value);
        }

        // Get role claims based on context
        var roleClaims = await GetContextualRoleClaims(user, tenantId, siteId);
        allClaims.AddRange(roleClaims);

        _logger.LogDebug("Generated {ClaimCount} total claims for user {UserId} with context tenant {TenantId}, site {SiteId}", 
            allClaims.Count, user.Id, tenantId, siteId);

        return allClaims;
    }

    private async Task<List<Role>> GetContextualRoles(AuthUser user, Guid? tenantId, Guid? siteId, bool includePermissions = true)
    {
        var allRoles = new List<Role>();
        
        // Always get Internal and Default roles
        var defaultRoles = await GetDefaultRolesWithPermissions(tenantId, siteId, includePermissions);
        var internalRoles = await GetUserRolesWithPermissions(user.Id, RoleScope.Internal, includePermissions: includePermissions);
        
        allRoles.AddRange(defaultRoles);
        allRoles.AddRange(internalRoles);
        
        // Add tenant roles if tenant context exists
        if (tenantId.HasValue)
        {
            var tenantRoles = await GetUserRolesWithPermissions(user.Id, RoleScope.Tenant, tenantId, includePermissions: includePermissions);
            allRoles.AddRange(tenantRoles);
        }
        
        // Add site roles if site context exists
        if (siteId.HasValue && tenantId.HasValue)
        {
            var siteRoles = await GetUserRolesWithPermissions(user.Id, RoleScope.Site, tenantId, siteId, includePermissions);
            allRoles.AddRange(siteRoles);
        }
        
        return allRoles;
    }

    private async Task<List<Role>> GetUserRolesWithPermissions(Guid userId, RoleScope scope, Guid? tenantId = null, Guid? siteId = null, bool includePermissions = true)
    {
        var query = _context.UserRoles
            .Where(ura => ura.UserId == userId && ura.Scope == scope);
            
        if (tenantId.HasValue)
            query = query.Where(ura => ura.TenantId == tenantId);
            
        if (siteId.HasValue)
            query = query.Where(ura => ura.SiteId == siteId);
            
        var roleIds = await query.Select(ura => ura.RoleId).ToListAsync();
        
        var roleQuery = _context.Roles.Where(r => roleIds.Contains(r.Id));
        
        if (includePermissions)
        {
            roleQuery = roleQuery
                .Include(r => r.RolePermissions)!
                    .ThenInclude(rp => rp.Permission);
        }
        
        return await roleQuery.ToListAsync();
    }

    private async Task<List<Role>> GetDefaultRolesWithPermissions(Guid? tenantId = null, Guid? siteId = null, bool includePermissions = true)
    {
        var queries = new List<IQueryable<Role>>();
        
        // Always include global default roles (no tenant, no site)
        queries.Add(_context.Roles.Where(r => r.Scope == RoleScope.Default && r.TenantId == null && r.SiteId == null));
        
        // Include tenant-specific default roles if we have a tenant context
        if (tenantId.HasValue)
        {
            queries.Add(_context.Roles.Where(r => r.Scope == RoleScope.Default && r.TenantId == tenantId && r.SiteId == null));
        }
        
        // Include site-specific default roles if we have a site context
        if (siteId.HasValue && tenantId.HasValue)
        {
            queries.Add(_context.Roles.Where(r => r.Scope == RoleScope.Default && r.TenantId == tenantId && r.SiteId == siteId));
        }
        
        // Union all queries
        var query = queries.Aggregate((q1, q2) => q1.Union(q2));
        
        if (includePermissions)
        {
            query = query
                .Include(r => r.RolePermissions)!
                    .ThenInclude(rp => rp.Permission);
        }
        
        return await query.ToListAsync();
    }

    private async Task<List<Claim>> GetContextualRoleClaims(AuthUser user, Guid? tenantId, Guid? siteId)
    {
        var allRoles = await GetContextualRoles(user, tenantId, siteId);
        
        // Create role claims - all roles in single array
        var roleClaims = new List<Claim>();
        var allRoleNames = allRoles.Select(r => r.Name).Distinct().ToArray();
        var roleJsonArray = JsonSerializer.Serialize(allRoleNames);
        roleClaims.Add(new Claim(CommonConstants.RolesClaim, roleJsonArray, JsonClaimValueTypes.JsonArray));
        
        _logger.LogDebug("Added role claims for user {UserId}: {Roles}", 
            user.Id, string.Join(", ", allRoleNames));

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

    public async Task<AuthTokenBundleWithRefresh> SwitchTenant(Guid userId, Guid tenantId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            throw new NotFoundException("User not found");
        }

        // Validate user has access to this tenant using UserService with forLogin=true
        var hasAccess = await _userService.HasTenantAccess(user.Id, tenantId, forLogin: true);
        
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

        // Generate new token bundle with tenant context
        var tokenBundle = await GenerateTokenBundle(user, tenantId, null);
        
        return tokenBundle;
    }

    public async Task<AuthTokenBundleWithRefresh> SwitchSite(Guid userId, Guid siteId)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
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

        // Validate user has access to this site with forLogin=true
        var hasSiteAccess = await _userService.HasSiteAccess(user.Id, siteId, site.TenantId, forLogin: true);
        
        if (!hasSiteAccess)
        {
            throw new InvalidDataException("User not assigned to this site");
        }

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

    public async Task<IEnumerable<TenantDto>> GetAvailableTenants(Guid userId)
    {
        return await _userService.GetUserTenants(userId, forLogin: true);
    }

    public async Task<IEnumerable<SiteDto>> GetAvailableSites(Guid userId, Guid tenantId)
    {
        return await _userService.GetUserSites(userId, tenantId, forLogin: true);
    }
    
    public async Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId, Guid? tenantId = null, Guid? siteId = null)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            throw new NotFoundException("User not found");
        }

        var allRoles = await GetContextualRoles(user, tenantId, siteId, includePermissions: true);
        
        // Extract permissions from roles
        var permissions = new HashSet<string>();
        foreach (var role in allRoles)
        {
            if (role.RolePermissions != null)
            {
                foreach (var rolePermission in role.RolePermissions)
                {
                    permissions.Add(rolePermission.Permission.Code);
                }
            }
        }
        
        return permissions.ToList();
    }
    
    public async Task<IEnumerable<RoleDto>> GetUserRolesAsync(Guid userId, Guid? tenantId = null, Guid? siteId = null)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString());
        if (user == null)
        {
            throw new NotFoundException("User not found");
        }

        var allRoles = await GetContextualRoles(user, tenantId, siteId, includePermissions: false);
        
        // Map to DTOs - roles without permissions
        var roleDtos = new List<RoleDto>();
        foreach (var role in allRoles)
        {
            var roleDto = new RoleDto
            {
                Id = role.Id.ToString(),
                Name = role.Name,
                Description = role.Description,
                Scope = role.Scope,
                TenantId = role.TenantId,
                SiteId = role.SiteId,
                IsSystemRole = role.IsSystemRole,
                Permissions = new List<PermissionDto>() // Empty permissions list
            };
            roleDtos.Add(roleDto);
        }
        
        return roleDtos;
    }
    
    public async Task<IdentityResult> RegisterViaInvitationAsync(RegisterViaInvitationRequest request)
    {
        // Validate invitation token
        var invitation = await _userService.ValidateInvitationTokenAsync(request.InvitationToken);
        if (invitation == null)
        {
            return IdentityResult.Failed(new IdentityError 
            { 
                Code = "InvalidInvitation", 
                Description = "Invalid or expired invitation token" 
            });
        }

        // Verify email matches invitation
        if (invitation.Email != request.Email)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "EmailMismatch",
                Description = "Email does not match invitation"
            });
        }

        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            // Check if this is a placeholder user (no password set)
            if (string.IsNullOrEmpty(existingUser.PasswordHash))
            {
                // Complete placeholder user registration by setting password
                var addPasswordResult = await _userManager.AddPasswordAsync(existingUser, request.Password);
                if (!addPasswordResult.Succeeded)
                {
                    return addPasswordResult;
                }
                
                // Confirm email for completed registration
                existingUser.EmailConfirmed = true;
                var updateResult = await _userManager.UpdateAsync(existingUser);
                if (!updateResult.Succeeded)
                {
                    return updateResult;
                }
                
                _logger.LogInformation("Completed placeholder user registration for email {Email}", request.Email);
            }
            else
            {
                // User already has password, just add them to tenant if needed
                await ProcessInvitationForExistingUser(existingUser, invitation);
            }
            
            // Mark invitation as used
            invitation.IsUsed = true;
            _context.UserInvitations.Update(invitation);
            await _uow.CompleteAsync();

            return IdentityResult.Success;
        }

        // This should rarely happen now since we create placeholder users
        // Create new user (fallback for edge cases)
        var newUser = new AuthUser
        {
            UserName = request.Email,
            Email = request.Email,
            EmailConfirmed = true // Email is confirmed via invitation
        };

        var createResult = await _userManager.CreateAsync(newUser, request.Password);
        if (!createResult.Succeeded)
        {
            return createResult;
        }

        // Process invitation for new user (only applies roles if stored in invitation)
        await ProcessInvitationForExistingUser(newUser, invitation);

        // Mark invitation as used
        invitation.IsUsed = true;
        _context.UserInvitations.Update(invitation);
        await _uow.CompleteAsync();

        // Send welcome email
        var welcomeEmailContent = await _emailContentService.PrepareWelcomeEmailAsync(newUser.Email!, newUser.UserName ?? newUser.Email!, invitation.TenantId);
        await _emailService.SendEmailAsync(welcomeEmailContent);

        // Publish user-created message
        var userCreatedMessage = new UserCreatedMessage
        {
            UserId = newUser.Id.ToString(),
            Email = newUser.Email!
        };
        await _snsService.PublishUserCreatedAsync(userCreatedMessage);

        return IdentityResult.Success;
    }

    private Task ProcessInvitationForExistingUser(AuthUser user, UserInvitation invitation)
    {
        // Roles are now assigned immediately during invitation creation
        // This method is kept for backwards compatibility but no longer applies roles
        // The user already has their roles assigned from the invitation process
        return Task.CompletedTask;
    }
}

public class JwtTokenReturn
{
    public required string AccessToken { get; set; }
    public required DateTime Expires { get; set; }
}