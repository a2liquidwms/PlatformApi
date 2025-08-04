using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NetStarterCommon.Core.Common.Constants;
using NetStarterCommon.Core.Common.Models;
using NetStarterCommon.Core.Common.Services;
using NetStarterCommon.Core.Common.Tenant;
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
    private readonly IHttpContextAccessor _httpContext;
    private readonly TenantHelper _tenantHelper;
    private readonly IOldUserService _oldUserService;
    private readonly IEmailService _emailService;
    private readonly IBrandingService _brandingService;
    private readonly ISnsService _snsService;
    private readonly string _refreshTokenDays;
    private readonly string _accessTokenMinutes;

    public AuthService(UserManager<AuthUser> userManager, SignInManager<AuthUser> signInManager,
        IConfiguration configuration, ILogger<AuthService> logger, PlatformDbContext context,
        IUnitOfWork<PlatformDbContext> uow, IHttpContextAccessor httpContext, TenantHelper tenantHelper, 
        IOldUserService oldUserService, IEmailService emailService, IBrandingService brandingService, ISnsService snsService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _logger = logger;
        _context = context;
        _uow = uow;
        _httpContext = httpContext;
        _tenantHelper = tenantHelper;
        _oldUserService = oldUserService;
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

    public async Task<AuthTokenBundle> Login(string email, string password, Guid? tenantId = null)
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
            await FetchAndSetTenant(user, (Guid)tenantId);
        }

        var token = await GenerateTokenBundle(user, tenantId);

        return token;
    }

    private async Task<bool> FetchAndSetTenant(AuthUser user, Guid tenantId)
    {
        //check for access
        var userTenants = await _oldUserService.GetUserTenants(user.Id.ToString());

        //if not part of tenant
        if (!userTenants.Any(t => t?.Id != null && t?.Id == tenantId))
        {
            //add to tenant as Guest
            var addUserResult = await _oldUserService.AddUserToRole(user.Id.ToString(), tenantId, Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE));
            if (!addUserResult)
            {
                throw new InvalidDataException("Could not add user to Guest role");
            }
        }

        //set context
        _httpContext.HttpContext!.Items[CommonConstants.TenantHttpContext] = tenantId;

        return true;
    }

    public async Task<AuthUser?> GetUserByEmail(string email)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    public async Task<AuthTokenBundle> ExternalLoginCallback(Guid? tenantId)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            throw new InvalidOperationException("Invalid login provider");
        }

        var email = info.Principal.FindFirstValue(ClaimTypes.Email);

        if (email == null)
        {
            throw new InvalidOperationException("Invalid email");
        }

        var user = await GetUserByEmail(email);

        if (user == null)
        {
            // Create new user if none exists
            user = new AuthUser
            {
                UserName = email, // Using email as username is more reliable
                Email = email,
                EmailConfirmed = true // Since it's verified by Google
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                _logger.LogError("Error Creating User Provider");
                _logger.LogError(createResult.Errors.ToString());
                throw new SystemException("Issue Creating User");
            }

            // Get branding context and send welcome email for external login users
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            await _emailService.SendWelcomeEmailAsync(user.Email!, user.UserName ?? user.Email!, branding);
            
            // Publish user-created message for external login users
            var userCreatedMessage = new UserCreatedMessage
            {
                UserId = user.Id.ToString(),
                Email = user.Email!
            };
            await _snsService.PublishUserCreatedAsync(userCreatedMessage);
        }

        // Add the external login provider to the user if it's not already there
        if (await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey) == null)
        {
            var addLoginResult = await _userManager.AddLoginAsync(user, info);
            if (!addLoginResult.Succeeded)
            {
                _logger.LogError("Error Creating User Provider");
                throw new SystemException("Issue Adding Provider");
            }
        }

        // Generate tokens
        return await GenerateTokenBundle(user, tenantId);
    }

    public async Task<bool> LinkProvider(ExternalLoginRequest request, ClaimsPrincipal user)
    {
        var validUser = await _userManager.GetUserAsync(user);
        if (user == null) throw new UnauthorizedAccessException();

        var loginInfo = new UserLoginInfo(request.Provider, request.ProviderKey, request.Provider);
        var result = await _userManager.AddLoginAsync(validUser!, loginInfo);

        if (!result.Succeeded) throw new SystemException(result.Errors.ToString());
        return true;
    }

    public async Task<bool> UnlinkProvider(UnlinkProviderRequest request, ClaimsPrincipal user)
    {
        var validUser = await _userManager.GetUserAsync(user);
        if (user == null) throw new UnauthorizedAccessException();

        var result = await _userManager.RemoveLoginAsync(validUser!, request.Provider, request.ProviderKey);

        if (!result.Succeeded) throw new SystemException(result.Errors.ToString());
        return true;
    }

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
        var tokenBundle = await GenerateTokenBundle(user, oldRefreshToken.TenantId);

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

    private async Task<AuthTokenBundle> GenerateTokenBundle(AuthUser user, Guid? tenantId = null)
    {
        var tokenReturn = await GenerateJwtToken(user, tenantId);
        var refreshToken = await GenerateRefreshToken(user, tenantId);

        return new AuthTokenBundle()
        {
            AccessToken = tokenReturn.AccessToken,
            TokenType = "Bearer",
            RefreshToken = refreshToken,
            Expires = (int)new DateTimeOffset(tokenReturn.Expires).ToUnixTimeSeconds(),
            TenantId = tenantId
        };
    }

    private async Task<JwtTokenReturn> GenerateJwtToken(AuthUser user, Guid? tenantId = null)
    {
        var issuer = _configuration["JWT_ISSUER"] ?? throw new InvalidOperationException("JWT_ISSUER is missing");
        var audience = _configuration["JWT_AUDIENCE"] ?? throw new InvalidOperationException("JWT_AUDIENCE is missing");
        var secretKey = _configuration["JWT_SECRET"] ?? throw new InvalidOperationException("JWT_SECRET is missing");
        var expiresEpoch = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_accessTokenMinutes));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = await GetAllClaims(user, tenantId);

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

    private async Task<List<Claim>> GetAllClaims(AuthUser user, Guid? tenantId = null)
    {
        var allClaims = new List<Claim>();
        var defaultClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(CommonConstants.ClaimUserId, user.Id.ToString())
        };
        allClaims.AddRange(defaultClaims);

        //get tenant claims
        var tenantClaims = await GetTenantClaims(user, tenantId);
        allClaims.AddRange(tenantClaims);
        
        var activeTenantClaim = tenantClaims.FirstOrDefault(c => c.Type == CommonConstants.ActiveTenantClaim);
        Guid? activeTenantId = null;
    
        if (activeTenantClaim != null && Guid.TryParse(activeTenantClaim.Value, out var parsedTenantId))
        {
            activeTenantId = parsedTenantId;
        }
        
        //get permission claims
        var roleClaims = await GetRoleClaims(user, activeTenantId);
        allClaims.AddRange(roleClaims);

        return allClaims;
    }

    private async Task<List<Claim>> GetRoleClaims(AuthUser user, Guid? tenant)
    {
        var roleClaims = new List<Claim>();
        var adminRoles = new List<Role>();

        var roles = await _oldUserService.GetUserRoles(user.Id.ToString(), tenant);
        // ReSharper disable once PossibleMultipleEnumeration
        var userRoleClaim = CreateClaimArray(roles.ToList(), CommonConstants.RolesClaim);
        roleClaims.Add(userRoleClaim);
        // ReSharper disable once PossibleMultipleEnumeration
        foreach (var r in roles)
        {
            if (r.IsSystemRole)
            {
                adminRoles.Add(r);
            }
        }

        if (adminRoles.Any())
        {
            var adminClaims = CreateClaimArray(adminRoles.ToList(), CommonConstants.AdminRolesClaim);
            roleClaims.Add(adminClaims);
        }

        return roleClaims;
    }

    private Claim CreateClaimArray(List<Role> roles, string claimKey)
    {
        // Extract role names and store them in a string array
        var roleNames = roles.Select(r => r.Name).ToArray();

        // Serialize the role names array to a properly formatted JSON string
        var roleJsonArray = JsonSerializer.Serialize(roleNames);
    
        // Return the claim with the JSON array value
        return new Claim(claimKey, roleJsonArray, JsonClaimValueTypes.JsonArray);
    }

    private async Task<List<Claim>> GetTenantClaims(AuthUser user, Guid? tenant)
    {
        var tenantClaims = new List<Claim>();
        var tenants = await _oldUserService.GetUserTenants(user.Id.ToString()) ?? new List<Tenant>();

        // Convert each tenant to an object with just the properties you need
        var tenantArray = tenants.Select(t => new TenantInfo { Id = t!.Id, Name = t.Name }).ToArray();

        // Serialize the tenant array to a JSON string
        var tenantJsonArray = JsonSerializer.Serialize(tenantArray);

        // Create a single claim with the JSON array as its value, and specify that its type is JSON.
        var tenantListClaim = new Claim(CommonConstants.TenantsClaim, tenantJsonArray, JsonClaimValueTypes.Json);
        tenantClaims.Add(tenantListClaim);

        if (tenant != null)
        {
            // Check if the provided tenant ID exists in the user's tenants
            // ReSharper disable once PossibleMultipleEnumeration
            var tenantExists = tenants.Any(t => t!.Id == tenant.Value);
        
            if (tenantExists)
            {
                var activeTenantClaim = new Claim(CommonConstants.ActiveTenantClaim, tenant.Value.ToString());
                tenantClaims.Add(activeTenantClaim);
            }
            else
            {
                throw new UnauthorizedAccessException($"Invalid Tenant ID or no Access: {tenant}");
            }
        }

        //set active if only one tenant exists
        if (tenant == null && tenantArray.Count() == 1)
        {
            var activeTenantClaim = new Claim(CommonConstants.ActiveTenantClaim, tenantArray[0].Id.ToString());
            tenantClaims.Add(activeTenantClaim);
        }

        return tenantClaims;
    }

    private async Task<string> GenerateRefreshToken(AuthUser user, Guid? tenantId = null)
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
            TenantId = tenantId
        };

        _context.RefreshTokens.Add(refreshToken);
        await _uow.CompleteAsync();

        return refreshToken.Token;
    }
    
    public async Task<IdentityResult> RegisterViaInvitationAsync(RegisterViaInvitationRequest request)
    {
        try
        {
            // Validate invitation token
            var invitation = await _oldUserService.ValidateInvitationTokenAsync(request.InvitationToken);
            if (invitation == null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "Invalid or expired invitation token"
                });
            }
            
            // Verify email matches invitation
            if (!string.Equals(invitation.Email, request.Email, StringComparison.OrdinalIgnoreCase))
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "Email does not match invitation"
                });
            }
            
            // Check if user already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Description = "User with this email already exists"
                });
            }
            
            // Create new user
            var user = new AuthUser
            {
                Email = request.Email,
                UserName = request.Email,
                EmailConfirmed = true // Skip email verification for invited users
            };
            
            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                return result;
            }
            
            // Add user to tenant
            await _oldUserService.AddUserToTenant(user.Id.ToString(), invitation.TenantId);
            
            // Assign roles if specified in invitation
            if (!string.IsNullOrEmpty(invitation.InvitedRoles))
            {
                try
                {
                    var roleIds = JsonSerializer.Deserialize<List<Guid>>(invitation.InvitedRoles);
                    if (roleIds != null)
                    {
                        foreach (var roleId in roleIds)
                        {
                            await _oldUserService.AddUserToRole(user.Id.ToString(), invitation.TenantId, roleId);
                        }
                    }
                }
                catch (JsonException ex)
                {
                    _logger.LogWarning(ex, "Failed to deserialize invited roles for user {UserId}", user.Id);
                }
            }
            
            // Mark invitation as used
            invitation.IsUsed = true;
            _context.UserInvitations.Update(invitation);
            await _uow.CompleteAsync();
            
            // Publish user created message
            var userCreatedMessage = new UserCreatedMessage
            {
                UserId = user.Id.ToString(),
                Email = user.Email!,
                CreatedAt = DateTime.UtcNow
            };
            await _snsService.PublishUserCreatedAsync(userCreatedMessage);
            
            _logger.LogInformation("User {Email} registered via invitation successfully", request.Email);
            
            return IdentityResult.Success;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during invitation-based registration for {Email}", request.Email);
            return IdentityResult.Failed(new IdentityError
            {
                Description = "Registration failed"
            });
        }
    }
}

public class JwtTokenReturn
{
    public required string AccessToken { get; set; }
    public required DateTime Expires { get; set; }
}