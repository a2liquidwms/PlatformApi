using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Auth;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Helpers;
using PlatformApi.Common.Tenant;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApi.Controllers;

[Route("api/v1/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IAuthService _authService;
    private readonly TenantHelper _tenantHelper;
    private readonly UserHelper _userHelper;
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;

    public AuthController(ILogger<AuthController> logger, IAuthService authService,
        TenantHelper tenantHelper, UserHelper userHelper, IConfiguration configuration, IWebHostEnvironment environment)
    {
        _logger = logger;
        _authService = authService;
        _tenantHelper = tenantHelper;
        _userHelper = userHelper;
        _configuration = configuration;
        _environment = environment;
    }

    private IActionResult HandleTokenResponse(AuthTokenBundleWithRefresh tokenBundle)
    {
        // Set refresh token as HttpOnly cookie
        if (!string.IsNullOrEmpty(tokenBundle.RefreshToken))
        {
            this.SetRefreshTokenCookie(tokenBundle.RefreshToken, _configuration, _environment);
        }
        
        // Return response with or without refresh token based on API testing header
        if (this.HasApiTestingHeader())
        {
            return Ok(tokenBundle); // Include refresh token for API testing
        }
        else
        {
            // Return only access token in response body for web apps (clean response)
            return Ok(new AuthTokenBundle
            {
                AccessToken = tokenBundle.AccessToken,
                TokenType = tokenBundle.TokenType,
                Expires = tokenBundle.Expires,
                TenantId = tokenBundle.TenantId,
                SiteId = tokenBundle.SiteId,
                TenantSubdomain = tokenBundle.TenantSubdomain
                // No refresh token property at all!
            });
        }
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
    {
        var tenantNullable = request.TenantId;

        var user = new AuthUser { UserName = request.Email, Email = request.Email };
        var result = await _authService.Register(user, request.Password, null, tenantNullable, null);

        if (!result.Succeeded)
        {
            _logger.LogWarning("User registration failed for {Email} with tenant {TenantId}. Errors: {Errors}", 
                request.Email, tenantNullable, string.Join(", ", result.Errors.Select(e => e.Description)));
            return BadRequest(result.Errors);
        }

        _logger.LogInformation("User {Email} registered successfully with tenant {TenantId}", 
            request.Email, tenantNullable);
        return Ok(new { Message = "User registered successfully" });
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        try
        {
            var token = await _authService.Login(request.Email, request.Password, request.TenantId, request.SiteId);
            return HandleTokenResponse(token);
        }
        catch (Exception e)
        {
            _logger.LogWarning("Login failed for user {Email} with tenant {TenantId} and site {SiteId}. Error: {Error}", 
                request.Email, request.TenantId, request.SiteId, e.Message);
            return BadRequest(e.Message);
        }
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        try
        {
            // Get current user ID from JWT token
            var userId = _userHelper.GetCurrentUserId();
            
            // Clear the refresh token cookie
            this.ClearRefreshTokenCookie(_configuration);
            
            // Revoke ALL refresh tokens for this user (logout everywhere)
            await _authService.Logout(userId);
            
            return Ok(new { Message = "Logged out successfully from all devices" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout for user {UserId}", _userHelper.GetCurrentUserId());
            // Still clear the cookie even if database operation fails
            this.ClearRefreshTokenCookie(_configuration);
            return Ok(new { Message = "Logged out successfully from all devices" });
        }
    }

    // [AllowAnonymous]
    // [HttpGet("login/{provider}")]
    // public IActionResult ExternalLogin(string provider, [FromQuery] string redirectUrl, Guid? tenantId = null)
    // {
    //     if (string.IsNullOrEmpty(redirectUrl))
    //     {
    //         return BadRequest("redirectUrl is required");
    //     }
    //
    //     // Validate that redirectUrl is from an allowed domain
    //     if (!IsValidRedirectUrl(redirectUrl))
    //     {
    //         _logger.LogWarning("Invalid redirect domain attempted: {RedirectUrl}", redirectUrl);
    //         return BadRequest("Invalid redirect URL domain");
    //     }
    //
    //     // Save the redirectUrl in the temporary cookie to retrieve in the callback
    //     var properties = _signInManager.ConfigureExternalAuthenticationProperties(
    //         provider,
    //         Url.Action(nameof(ExternalLoginCallback), "Auth", null, Request.Scheme)
    //     );
    //
    //     // Store redirectUrl in the AuthenticationProperties
    //     properties.Items["redirectUrl"] = redirectUrl;
    //     properties.Items["tenantId"] = tenantId.ToString();
    //
    //     // Challenge with the provider and properties
    //     return Challenge(properties, provider);
    // }

    // [AllowAnonymous]
    // [HttpGet("external-login-callback")]
    // public async Task<IActionResult> ExternalLoginCallback()
    // {
    //     // Get the login info and check for errors
    //     var info = await _signInManager.GetExternalLoginInfoAsync();
    //     if (info == null)
    //     {
    //         return RedirectToAction("Login", new { error = "External_login_failed" });
    //     }
    //
    //     // Retrieve the redirectUrl from the authentication properties
    //     var redirectUrl = info.AuthenticationProperties?.Items["redirectUrl"] ?? "/";
    //     var inputTenantId = info.AuthenticationProperties?.Items["tenantId"] ?? null;
    //
    //     Guid? tenantId = null;
    //
    //     if (!string.IsNullOrEmpty(inputTenantId))
    //     {
    //         if (Guid.TryParse(inputTenantId, out var parsedTenantId))
    //         {
    //             tenantId = parsedTenantId;
    //         }
    //         else
    //         {
    //             throw new InvalidDataException("Invalid tenant ID format.");
    //         }
    //     }
    //
    //     try
    //     {
    //         var tokenBundle = await _authService.ExternalLoginCallback(tenantId);
    //         var redirectParams =
    //             $"token={tokenBundle.AccessToken}&refreshToken={tokenBundle.RefreshToken}&tokenType={tokenBundle.TokenType}&expires={tokenBundle.Expires}";
    //
    //         if (tenantId.HasValue)
    //         {
    //             redirectParams += $"&tenantId={tenantId}";
    //         }
    //
    //         return Redirect($"{redirectUrl}?{redirectParams}");
    //      }
    //     catch (Exception ex)
    //     {
    //         _logger.LogError(ex, "External login callback failed");
    //         return Redirect($"{redirectUrl}?error=External_login_failed");
    //     }
    // }

    [AllowAnonymous]
    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest request)
    {
        try
        {
            var result = await _authService.ConfirmEmailAsync(request.UserId, request.Token, null, request.TenantId);

            if (result)
            {
                return Ok(new { Message = "Email confirmed successfully! You can now log in." });
            }

            _logger.LogWarning("Email confirmation failed for user {UserId} with tenant {TenantId} - invalid or expired token", 
                request.UserId, request.TenantId);
            return BadRequest("Invalid or expired email confirmation token.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming email for user {UserId}", request.UserId);
            return BadRequest("Failed to confirm email. Please try again or request a new confirmation email.");
        }
    }

    [AllowAnonymous]
    [HttpPost("resend-confirmation")]
    public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
    {
        try
        {
            var result = await _authService.SendEmailConfirmationAsync(request.Email, null, request.TenantId, null);

            if (result)
            {
                return Ok(new { Message = "If the email address is registered, a confirmation email has been sent." });
            }

            _logger.LogError("Error resending confirmation email to {Email}", request.Email);
            return BadRequest("There was an unexpected error while sending a confirmation email.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resending confirmation email to {Email}", request.Email);
            return BadRequest("There was an unexpected error while sending a confirmation email.");
        }
    }

    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        try
        {
            await _authService.SendPasswordResetAsync(request.Email, null, request.TenantId);
            
            return Ok(new { Message = "If the email address is registered, a password reset email has been sent." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending password reset email to {Email}", request.Email);
            return Ok(new { Message = "If the email address is registered, a password reset email has been sent." });
        }
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        try
        {
            var result = await _authService.ResetPasswordAsync(request.UserId, request.Token, request.NewPassword, null,
                request.TenantId);

            if (result)
            {
                return Ok(new { Message = "Password reset successfully! You can now log in with your new password." });
            }

            _logger.LogWarning("Password reset failed for user {UserId} with tenant {TenantId} - invalid or expired token", 
                request.UserId, request.TenantId);
            return BadRequest("Invalid or expired password reset token.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for user {UserId}", request.UserId);
            return BadRequest("Failed to reset password. Please try again or request a new password reset email.");
        }
    }

    // [HttpPost("link-provider")]
    // public async Task<IActionResult> LinkProvider([FromBody] ExternalLoginRequest request)
    // {
    //     try
    //     {
    //         var result = await _authService.LinkProvider(request, User);
    //         if (!result) return BadRequest();
    //
    //         return Ok(new { Message = "Provider linked successfully" });
    //     }
    //     catch (UnauthorizedAccessException)
    //     {
    //         return Unauthorized();
    //     }
    //     catch (Exception)
    //     {
    //         return BadRequest();
    //     }
    // }
    //
    // [HttpPost("unlink-provider")]
    // public async Task<IActionResult> UnlinkProvider([FromBody] UnlinkProviderRequest request)
    // {
    //     try
    //     {
    //         var result = await _authService.UnlinkProvider(request, User);
    //         if (!result) return BadRequest();
    //
    //         return Ok(new { Message = "Provider unlinked successfully" });
    //     }
    //     catch (UnauthorizedAccessException)
    //     {
    //         return Unauthorized();
    //     }
    //     catch (Exception)
    //     {
    //         return BadRequest();
    //     }
    // }
    
    [AllowAnonymous]
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        try
        {
            // only looks at cookie.  No current way to handle refresh via Postman 
            var refreshToken = this.GetRefreshTokenFromCookie();
            
            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("Token refresh attempted without refresh token");
                return BadRequest("Refresh token is required either in cookie or request body");
            }
            
            var tokenBundle = await _authService.RefreshToken(refreshToken);
            return HandleTokenResponse(tokenBundle);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Token refresh failed: {Error}", ex.Message);
            // Clear the refresh token cookie if refresh failed
            this.ClearRefreshTokenCookie(_configuration);
            return Unauthorized("Invalid or Expired token");
        }
    }

    [AllowAnonymous]
    [HttpPost("register-invitation")]
    public async Task<IActionResult> RegisterViaInvitation([FromBody] RegisterViaInvitationRequest request)
    {
        try
        {
            var result = await _authService.RegisterViaInvitationAsync(request);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            
            return Ok(new { Message = "User registered successfully. Please log in with your credentials." });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during invitation-based registration for {Email}", request.Email);
            return BadRequest(new { Message = "Registration failed" });
        }
    }

    [Authorize]
    [HttpGet("my/permissions")]
    public async Task<ActionResult<IEnumerable<string>>> GetMyPermissions()
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
            var tenantId = _tenantHelper.GetTenantId() != Guid.Empty ? _tenantHelper.GetTenantId() : (Guid?)null;
            var siteId = _tenantHelper.GetSiteId() != Guid.Empty ? _tenantHelper.GetSiteId() : (Guid?)null;
            var permissions = await _authService.GetUserPermissionsAsync(userId, tenantId, siteId);
            return Ok(permissions);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving permissions for user");
            return StatusCode(500, "Internal server error");
        }
    }

    [Authorize]
    [HttpGet("my/roles")]
    public async Task<ActionResult<IEnumerable<RoleDto>>> GetMyRoles()
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
            var tenantId = _tenantHelper.GetTenantId() != Guid.Empty ? _tenantHelper.GetTenantId() : (Guid?)null;
            var siteId = _tenantHelper.GetSiteId() != Guid.Empty ? _tenantHelper.GetSiteId() : (Guid?)null;
            var roles = await _authService.GetUserRolesAsync(userId, tenantId, siteId);
            return Ok(roles);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            return BadRequest(ex.Message);
        }
        catch (NotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving roles for user");
            return StatusCode(500, "Internal server error");
        }
    }

    [Authorize]
    [HttpPost("switch-tenant")]
    public async Task<IActionResult> SwitchTenant([FromBody] SwitchTenantRequest request)
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
            var tokenBundle = await _authService.SwitchTenant(userId, request.TenantId);
            _logger.LogInformation("User {UserId} switched to tenant {TenantId} successfully", 
                userId, request.TenantId);
            return HandleTokenResponse(tokenBundle);
        }
        catch (NotFoundException ex)
        {
            _logger.LogWarning("Tenant switch failed for user {UserId} to tenant {TenantId} - not found: {Error}", 
                _userHelper.GetCurrentUserId(), request.TenantId, ex.Message);
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Tenant switch failed for user {UserId} to tenant {TenantId} - access denied: {Error}", 
                _userHelper.GetCurrentUserId(), request.TenantId, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error switching tenant for user {UserId} to tenant {TenantId}", _userHelper.GetCurrentUserId(), request.TenantId);
            return StatusCode(500, "Internal server error");
        }
    }

    [Authorize]
    [HttpPost("switch-site")]
    public async Task<IActionResult> SwitchSite([FromBody] SwitchSiteRequest request)
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
            var tokenBundle = await _authService.SwitchSite(userId, request.SiteId);
            _logger.LogInformation("User {UserId} switched to site {SiteId} successfully", 
                userId, request.SiteId);
            return HandleTokenResponse(tokenBundle);
        }
        catch (NotFoundException ex)
        {
            _logger.LogWarning("Site switch failed for user {UserId} to site {SiteId} - not found: {Error}", 
                _userHelper.GetCurrentUserId(), request.SiteId, ex.Message);
            return NotFound(ex.Message);
        }
        catch (InvalidDataException ex)
        {
            _logger.LogWarning("Site switch failed for user {UserId} to site {SiteId} - access denied: {Error}", 
                _userHelper.GetCurrentUserId(), request.SiteId, ex.Message);
            return BadRequest(ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error switching site for user {UserId} to site {SiteId}", _userHelper.GetCurrentUserId(), request.SiteId);
            return StatusCode(500, "Internal server error");
        }
    }
}