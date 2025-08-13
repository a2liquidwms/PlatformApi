using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Auth;
using PlatformApi.Common.Constants;
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

    public AuthController(ILogger<AuthController> logger, IAuthService authService,
        TenantHelper tenantHelper, UserHelper userHelper)
    {
        _logger = logger;
        _authService = authService;
        _tenantHelper = tenantHelper;
        _userHelper = userHelper;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
    {
        Guid? tenantNullable = null;
        var tenantId = _tenantHelper.GetTenantId();
        if (tenantId != Guid.Empty)
        {
            tenantNullable = tenantId;
        }

        var user = new AuthUser { UserName = request.Email, Email = request.Email };
        var result = await _authService.Register(user, request.Password, null, tenantNullable, null);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok(new { Message = "User registered successfully" });
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<ActionResult<AuthTokenBundle>> Login([FromBody] LoginRequest request)
    {
        try
        {
            var token = await _authService.Login(request.Email, request.Password, request.TenantId, request.SiteId);
            return Ok(token);
        }
        catch (Exception e)
        {
            return BadRequest(e.Message);
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
            Guid? tenantNullable = null;
            var tenantId = _tenantHelper.GetTenantId();
            if (tenantId != Guid.Empty)
            {
                tenantNullable = tenantId;
            }

            var result = await _authService.ConfirmEmailAsync(request.UserId, request.Token, null, tenantNullable);

            if (result)
            {
                return Ok(new { Message = "Email confirmed successfully! You can now log in." });
            }

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
            Guid? tenantNullable = null;
            var tenantId = _tenantHelper.GetTenantId();
            if (tenantId != Guid.Empty)
            {
                tenantNullable = tenantId;
            }

            var result = await _authService.SendEmailConfirmationAsync(request.Email, null, tenantNullable, null);

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
            Guid? tenantNullable = null;
            var tenantId = _tenantHelper.GetTenantId();
            if (tenantId != Guid.Empty)
            {
                tenantNullable = tenantId;
            }

            await _authService.SendPasswordResetAsync(request.Email, null, tenantNullable);

            // Always return success to prevent email enumeration
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
            Guid? tenantNullable = null;
            var tenantId = _tenantHelper.GetTenantId();
            if (tenantId != Guid.Empty)
            {
                tenantNullable = tenantId;
            }

            var result = await _authService.ResetPasswordAsync(request.UserId, request.Token, request.NewPassword, null,
                tenantNullable);

            if (result)
            {
                return Ok(new { Message = "Password reset successfully! You can now log in with your new password." });
            }

            return BadRequest("Invalid or expired password reset token.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for user {UserId}", request.UserId);
            return BadRequest("Failed to reset password. Please try again or request a new password reset email.");
        }
    }

    // private bool IsValidRedirectUrl(string url)
    // {
    //     try
    //     {
    //         // Parse the URL to check its domain
    //         var uri = new Uri(url);
    //
    //         // Get allowed domains from environment variable
    //         var allowedDomainsEnv = Environment.GetEnvironmentVariable("ALLOWED_REDIRECT_DOMAINS") ?? "";
    //
    //         return IsHostAllowed(uri.ToString(), allowedDomainsEnv);
    //     }
    //     catch
    //     {
    //         // If URL is malformed or any other error
    //         return false;
    //     }
    // }

    // private bool IsHostAllowed(string host, string allowedDomainsString)
    // {
    //     // If wildcard is specified, allow all domains
    //     if (allowedDomainsString.Equals("*"))
    //     {
    //         return true;
    //     }
    //
    //     // If empty, use a default domain (optional - you might want to be strict and return false)
    //     if (string.IsNullOrWhiteSpace(allowedDomainsString))
    //     {
    //         _logger.LogWarning("Missing Config - allowed domain string: {AllowedDomainsString}", allowedDomainsString);
    //         return false;
    //     }
    //     // if (string.IsNullOrWhiteSpace(allowedDomainsString))
    //     // {
    //     //     var defaultDomain = Environment.GetEnvironmentVariable("APPLICATION_DOMAIN");
    //     //     return !string.IsNullOrEmpty(defaultDomain) && 
    //     //            (host.Equals(defaultDomain, StringComparison.OrdinalIgnoreCase) || 
    //     //             host.EndsWith($".{defaultDomain}", StringComparison.OrdinalIgnoreCase));
    //     // }
    //
    //     // Split the comma-separated domains and check if host matches or is a subdomain
    //     var allowedDomains = allowedDomainsString.Split(',', StringSplitOptions.RemoveEmptyEntries)
    //         .Select(d => d.Trim())
    //         .ToList();
    //
    //     return allowedDomains.Any(domain =>
    //         host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
    //         host.EndsWith($".{domain}", StringComparison.OrdinalIgnoreCase));
    // }

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
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        try
        {
            var tokenBundle = await _authService.RefreshToken(request.UserId, request.RefreshToken);
            return Ok(tokenBundle);
        }
        catch (Exception)
        {
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

            _logger.LogInformation("User {Email} registered successfully via invitation", request.Email);
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
    public async Task<ActionResult<IEnumerable<string>>> GetMyPermissions([FromQuery] Guid? tenantId = null,
        [FromQuery] Guid? siteId = null)
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
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
    public async Task<ActionResult<IEnumerable<RoleDto>>> GetMyRoles([FromQuery] Guid? tenantId = null,
        [FromQuery] Guid? siteId = null)
    {
        try
        {
            var userId = _userHelper.GetCurrentUserId();
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
}