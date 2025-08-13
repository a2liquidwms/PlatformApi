using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Common.Constants;
using PlatformApi.Common.Tenant;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;

namespace PlatformApi.Controllers;

[Route("auth")]
[AllowAnonymous]
public class AuthPagesController : Controller
{
    private readonly IAuthService _authService;
    private readonly IBrandingService _brandingService;
    private readonly ITenantService _tenantService;
    private readonly TenantHelper _tenantHelper;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthPagesController> _logger;

    public AuthPagesController(
        IAuthService authService,
        IBrandingService brandingService,
        ITenantService tenantService,
        TenantHelper tenantHelper,
        IConfiguration configuration,
        ILogger<AuthPagesController> logger)
    {
        _authService = authService;
        _brandingService = brandingService;
        _tenantService = tenantService;
        _tenantHelper = tenantHelper;
        _configuration = configuration;
        _logger = logger;
    }


    private async Task<(Guid TenantId, string? ErrorMessage)> GetTenantIdForAuthPagesAsync()
    {
        string? subdomain = null;

        // First try to get tenant subdomain from X-Tenant-Subdomain header (for nginx/production scenarios)
        if (Request.Headers.TryGetValue(CommonConstants.TenantHeaderSubdomain, out var headerSubdomainValue) &&
            !string.IsNullOrWhiteSpace(headerSubdomainValue))
        {
            subdomain = headerSubdomainValue;
        }
        // Fallback to query parameter (for local development)
        else if (Request.Query.TryGetValue("tenant", out var tenantSubdomainValue) && 
            !string.IsNullOrWhiteSpace(tenantSubdomainValue))
        {
            subdomain = tenantSubdomainValue;
        }

        // If we have a subdomain, look up the tenant
        if (!string.IsNullOrWhiteSpace(subdomain))
        {
            try
            {
                var tenantConfig = await _tenantService.GetTenantConfigBySubdomain(subdomain);
                if (tenantConfig != null)
                {
                    return (tenantConfig.TenantId, null);
                }
                else
                {
                    _logger.LogWarning("Tenant not found for subdomain: {Subdomain}", subdomain);
                    return (Guid.Empty, $"Tenant '{subdomain}' not found. Please check the tenant name or contact your administrator.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error looking up tenant for subdomain: {Subdomain}", subdomain);
                return (Guid.Empty, "An error occurred while looking up the tenant. Please try again later.");
            }
        }

        return (Guid.Empty, null);
    }

    private string GetCookieDomain()
    {
        var baseDomain = _configuration["UI_BASE_DOMAIN"];
        if (string.IsNullOrEmpty(baseDomain))
        {
            return ""; // No domain restriction for development
        }

        // Extract the root domain for cross-subdomain sharing
        // If baseDomain is "localhost:5173" (dev) return empty string
        // If baseDomain is "mysite.com" return ".mysite.com"
        if (baseDomain.Contains("localhost"))
        {
            return ""; // Localhost doesn't support domain cookies
        }

        // Remove port and add leading dot for subdomain sharing
        var domain = baseDomain.Split(':')[0];
        return $".{domain}";
    }

    /// <summary>
    /// Helper method to validate tenant and setup branding for auth pages.
    /// Returns null if valid tenant found or no tenant specified.
    /// Returns IActionResult redirect to error page if tenant lookup fails.
    /// </summary>
    private async Task<(IActionResult? ErrorResult, Guid? TenantId)> ValidateTenantAndSetupBrandingAsync()
    {
        var (foundTenantId, tenantError) = await GetTenantIdForAuthPagesAsync();
        
        // If tenant lookup failed, redirect to error page
        if (!string.IsNullOrEmpty(tenantError))
        {
            return (RedirectToAction("TenantError", new { message = tenantError }), null);
        }
        
        var tenantId = foundTenantId != Guid.Empty ? foundTenantId : (Guid?)null;
        ViewBag.Branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
        
        return (null, tenantId);
    }

    #region Error Pages
    [HttpGet("tenant-error")]
    public async Task<IActionResult> TenantError(string? message = null)
    {
        ViewBag.Branding = await _brandingService.GetDefaultBrandingContextAsync();
        ViewBag.ErrorMessage = message ?? "Tenant not found. Please check the tenant name or contact your administrator.";
        return View();
    }
    #endregion

    #region Login
    [HttpGet("login")]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.ReturnUrl = returnUrl;
        return View();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginInputModel model, string? returnUrl = null)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.ReturnUrl = returnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            var tokenBundle = await _authService.Login(model.Email, model.Password, tenantId, model.SiteId);

            if (tokenBundle != null)
            {
                // Set secure cross-subdomain cookies
                var cookieDomain = GetCookieDomain();
                var isProduction = _configuration["ASPNETCORE_ENVIRONMENT"] != "Development";
                
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = isProduction, // Only require HTTPS in production
                    SameSite = SameSiteMode.Lax, // Allow cross-subdomain navigation
                    Expires = DateTimeOffset.UtcNow.AddSeconds(tokenBundle.Expires)
                };

                // Set domain for cross-subdomain sharing (only if not localhost)
                if (!string.IsNullOrEmpty(cookieDomain))
                {
                    cookieOptions.Domain = cookieDomain;
                }

                if (!string.IsNullOrEmpty(tokenBundle.AccessToken))
                {
                    Response.Cookies.Append("access_token", tokenBundle.AccessToken, cookieOptions);
                }
                
                // Refresh token with longer expiration
                if (!string.IsNullOrEmpty(tokenBundle.RefreshToken))
                {
                    var refreshCookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = isProduction,
                        SameSite = SameSiteMode.Lax
                    };

                    if (!string.IsNullOrEmpty(cookieDomain))
                    {
                        refreshCookieOptions.Domain = cookieDomain;
                    }

                    Response.Cookies.Append("refresh_token", tokenBundle.RefreshToken, refreshCookieOptions);
                }
                
                // Redirect back to the requesting URL
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                {
                    return Redirect(returnUrl);
                }
                
                // Fallback success message if no return URL
                ViewBag.SuccessMessage = "Login successful! You can now access the application.";
                return View(model);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid Login");
                return View(model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login failed for user {Email}", model.Email);
            ModelState.AddModelError(string.Empty, "Invalid Login");
            return View(model);
        }
    }
    #endregion

    #region Register
    [HttpGet("register")]
    public async Task<IActionResult> Register()
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        return View();
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterInputModel model)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            var user = new AuthUser 
            { 
                UserName = model.Email, 
                Email = model.Email 
            };

            var result = await _authService.Register(user, model.Password, null, tenantId);

            if (result.Succeeded)
            {
                ViewBag.SuccessMessage = "Registration successful! Please check your email for a confirmation link.";
                ModelState.Clear();
                return View();
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration failed for user {Email}", model.Email);
            ModelState.AddModelError(string.Empty, "Registration failed. Please try again.");
            return View(model);
        }
    }
    #endregion

    #region Forgot Password
    [HttpGet("forgot-password")]
    public async Task<IActionResult> ForgotPassword()
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        return View();
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordInputModel model)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {

            await _authService.SendPasswordResetAsync(model.Email, null, tenantId);

            ViewBag.SuccessMessage = "If the email address is registered, a password reset email has been sent. Please check your inbox and follow the instructions.";
            ModelState.Clear();
            return View();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending password reset email to {Email}", model.Email);
            ViewBag.SuccessMessage = "If the email address is registered, a password reset email has been sent. Please check your inbox and follow the instructions.";
            return View(model);
        }
    }
    #endregion

    #region Reset Password
    [HttpGet("reset-password")]
    public async Task<IActionResult> ResetPassword(string? userId = null, string? token = null)
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            ModelState.AddModelError(string.Empty, "Invalid password reset link. Please request a new password reset.");
            return View();
        }

        if (!Guid.TryParse(userId, out var parsedUserId))
        {
            ModelState.AddModelError(string.Empty, "Invalid password reset link. Please request a new password reset.");
            return View();
        }

        var model = new ResetPasswordInputModel
        {
            UserId = parsedUserId,
            Token = token
        };

        return View(model);
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordInputModel model)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (model.UserId == Guid.Empty || string.IsNullOrEmpty(model.Token))
        {
            ModelState.AddModelError(string.Empty, "Invalid password reset request. Please request a new password reset.");
            return View(model);
        }

        try
        {

            var result = await _authService.ResetPasswordAsync(model.UserId, model.Token, model.NewPassword, null, tenantId);

            if (result)
            {
                ViewBag.SuccessMessage = "Password reset successfully! You can now sign in with your new password.";
                return RedirectToAction("Login");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid or expired password reset token. Please request a new password reset.");
                return View(model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for user {UserId}", model.UserId);
            ModelState.AddModelError(string.Empty, "Failed to reset password. Please try again or request a new password reset.");
            return View(model);
        }
    }
    #endregion

    #region Register Invitation
    [HttpGet("register-invitation")]
    public async Task<IActionResult> RegisterInvitation(string? email = null, string? token = null, string? invitationId = null)
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(invitationId))
        {
            ModelState.AddModelError(string.Empty, "Invalid invitation link. Please contact your administrator for a new invitation.");
            return View();
        }

        if (!Guid.TryParse(invitationId, out var parsedInvitationId))
        {
            ModelState.AddModelError(string.Empty, "Invalid invitation link. Please contact your administrator for a new invitation.");
            return View();
        }

        ViewBag.InvitationEmail = email;

        var model = new RegisterInvitationInputModel
        {
            Email = email,
            Token = token,
            InvitationId = parsedInvitationId
        };

        return View(model);
    }

    [HttpPost("register-invitation")]
    public async Task<IActionResult> RegisterInvitation(RegisterInvitationInputModel model)
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.InvitationEmail = model.Email;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        if (model.InvitationId == Guid.Empty || string.IsNullOrEmpty(model.Token))
        {
            ModelState.AddModelError(string.Empty, "Invalid invitation request. Please contact your administrator for a new invitation.");
            return View(model);
        }

        try
        {
            var request = new RegisterViaInvitationRequest
            {
                Email = model.Email,
                Password = model.Password,
                InvitationToken = model.Token
            };

            var result = await _authService.RegisterViaInvitationAsync(request);

            if (result.Succeeded)
            {
                ViewBag.SuccessMessage = "Registration successful! You can now sign in with your credentials.";
                return RedirectToAction("Login");
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Invitation registration failed for user {Email}", model.Email);
            ModelState.AddModelError(string.Empty, "Registration failed. The invitation may have expired. Please contact your administrator.");
            return View(model);
        }
    }
    #endregion

    #region Confirm Email
    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail(string? userId = null, string? token = null, string? email = null)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
        {
            ViewBag.IsConfirmed = false;
            ModelState.AddModelError(string.Empty, "Invalid email confirmation link. Please try registering again or contact support.");
            return View();
        }

        if (!Guid.TryParse(userId, out var parsedUserId))
        {
            ViewBag.IsConfirmed = false;
            ModelState.AddModelError(string.Empty, "Invalid email confirmation link. Please try registering again or contact support.");
            return View();
        }

        try
        {

            var result = await _authService.ConfirmEmailAsync(parsedUserId, token, null, tenantId);

            if (result)
            {
                ViewBag.IsConfirmed = true;
                ViewBag.UserEmail = email ?? "your email";
                ViewBag.SuccessMessage = "Email confirmed successfully! You can now sign in with your credentials.";
            }
            else
            {
                ViewBag.IsConfirmed = false;
                ModelState.AddModelError(string.Empty, "Invalid or expired email confirmation token. Please try registering again or request a new confirmation email.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error confirming email for user {UserId}", parsedUserId);
            ViewBag.IsConfirmed = false;
            ModelState.AddModelError(string.Empty, "Failed to confirm email. Please try again or contact support.");
        }

        return View();
    }

    [HttpPost("confirm-email")]
    public async Task<IActionResult> ResendConfirmation(string email)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        if (string.IsNullOrEmpty(email))
        {
            ModelState.AddModelError(string.Empty, "Email address is required to resend confirmation.");
            return View("ConfirmEmail");
        }

        try
        {

            var result = await _authService.SendEmailConfirmationAsync(email, null, tenantId);

            if (result)
            {
                ViewBag.SuccessMessage = "A new confirmation email has been sent. Please check your inbox.";
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Failed to send confirmation email. Please try again later.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resending confirmation email to {Email}", email);
            ModelState.AddModelError(string.Empty, "Failed to send confirmation email. Please try again later.");
        }

        return View("ConfirmEmail");
    }
    #endregion
}

#region Input Models
public class LoginInputModel
{
    [Required(ErrorMessage = "Email is required2")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public Guid? TenantId { get; set; }
    public Guid? SiteId { get; set; }
    public bool RememberMe { get; set; }
}

public class RegisterInputModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public class ForgotPasswordInputModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address")]
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordInputModel
{
    public Guid UserId { get; set; }
    public string Token { get; set; } = string.Empty;

    [Required(ErrorMessage = "New password is required")]
    [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your new password")]
    [DataType(DataType.Password)]
    [Compare("NewPassword", ErrorMessage = "New password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public class RegisterInvitationInputModel
{
    public Guid InvitationId { get; set; }
    public string Token { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [DataType(DataType.Password)]
    [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;
}
#endregion