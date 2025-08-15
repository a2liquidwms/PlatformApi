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
    private readonly string _defaultReturnUrl;

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

        // Validate required environment variables at startup
        _defaultReturnUrl = _configuration["DEFAULT_RETURN_URL"] ?? throw new InvalidOperationException("DEFAULT_RETURN_URL environment variable is not configured");
    }


    private async Task<Guid?> GetTenantIdForAuthPagesAsync()
    {
        string? subdomain = ExtractSubdomainFromRequest();

        // If we have a subdomain, look up the tenant
        if (!string.IsNullOrWhiteSpace(subdomain))
        {
            var tenantConfig = await _tenantService.GetTenantConfigBySubdomain(subdomain);
            if (tenantConfig == null)
            {
                _logger.LogWarning("Tenant not found for subdomain: {Subdomain}", subdomain);
                throw new NotFoundException($"Tenant '{subdomain}' not found. Please check the tenant name or contact your administrator.");
            }
            return tenantConfig.TenantId;
        }

        // No subdomain found - use default platform tenant
        return null;
    }

    /// <summary>
    /// Extracts the tenant subdomain from the current request URL using AUTH_BASE_DOMAIN as reference.
    /// Example: tenant1.auth.myapp.local:5201 with base auth.myapp.local:5201 returns "tenant1"
    /// </summary>
    private string? ExtractSubdomainFromRequest()
    {
        try
        {
            var currentHost = Request.Host.Value;
            var baseDomain = _configuration["AUTH_BASE_DOMAIN"];
            
            if (string.IsNullOrWhiteSpace(baseDomain))
            {
                _logger.LogWarning("AUTH_BASE_DOMAIN not configured");
                return null;
            }

            _logger.LogDebug("Extracting subdomain from host: {CurrentHost}, base: {BaseDomain}", currentHost, baseDomain);

            // If current host is exactly the base domain, no subdomain
            if (currentHost.Equals(baseDomain, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            // Extract subdomain by removing base domain suffix
            if (currentHost.EndsWith($".{baseDomain}", StringComparison.OrdinalIgnoreCase))
            {
                var subdomain = currentHost.Substring(0, currentHost.Length - baseDomain.Length - 1);
                _logger.LogDebug("Extracted subdomain: {Subdomain}", subdomain);
                return subdomain;
            }

            _logger.LogDebug("No subdomain pattern match for host: {CurrentHost}", currentHost);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting subdomain from request");
            return null;
        }
    }



    /// <summary>
    /// Helper method to validate tenant and setup branding for auth pages.
    /// Returns tenant ID if found, null for default platform.
    /// Throws NotFoundException if tenant subdomain lookup fails.
    /// </summary>
    private async Task<Guid?> ValidateTenantAndSetupBrandingAsync()
    {
        var tenantId = await GetTenantIdForAuthPagesAsync();
        ViewBag.Branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
        return tenantId;
    }

    /// <summary>
    /// Gets a safe redirect URL that only allows configured UI domains.
    /// Falls back to DEFAULT_RETURN_URL if returnUrl is not provided or not allowed.
    /// </summary>
    private string GetSafeRedirectUrl(string? returnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl) && IsAllowedDomain(returnUrl))
        {
            return returnUrl;
        }
        return _defaultReturnUrl;
    }

    /// <summary>
    /// Validates if a URL belongs to an allowed domain for redirects.
    /// Only allows configured UI domains for security.
    /// </summary>
    private bool IsAllowedDomain(string url)
    {
        try
        {
            var uri = new Uri(url);

            // Check against AUTH_COOKIE_DOMAIN (root domain for UI apps)
            var cookieDomain = _configuration["AUTH_COOKIE_DOMAIN"];
            if (!string.IsNullOrEmpty(cookieDomain))
            {
                var rootDomain = cookieDomain.TrimStart('.'); // Remove leading dot if present
                return uri.Host.EndsWith($".{rootDomain}") || uri.Host.Equals(rootDomain, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }
        catch (UriFormatException)
        {
            return false;
        }
    }


    /// <summary>
    /// Clears authentication cookies by setting them to expired
    /// </summary>
    private void ClearAuthCookies()
    {
        var cookieDomain = _configuration["AUTH_COOKIE_DOMAIN"];
        var isSecure = Request.Scheme == "https";
        var secureFlag = isSecure ? "; secure" : "";
        var expires = DateTimeOffset.UtcNow.AddDays(-1); // Expire in the past to delete

        var clearCookieValue = $"; expires={expires:ddd, dd MMM yyyy HH:mm:ss} GMT; domain={cookieDomain}; path=/; samesite=lax; httponly{secureFlag}";
        Response.Headers.Append("Set-Cookie", $"access_token={clearCookieValue}");
        Response.Headers.Append("Set-Cookie", $"refresh_token={clearCookieValue}");
        
        _logger.LogInformation("Cleared existing authentication cookies");
    }

    /// <summary>
    /// Generates authentication cookies using environment configuration
    /// </summary>
    private void GenerateAuthCookies(AuthTokenBundle tokenBundle)
    {
        var cookieDomain = _configuration["AUTH_COOKIE_DOMAIN"]; // e.g., ".myapp.local" or ".yourdomain.com"
        var isSecure = Request.Scheme == "https"; // Auto-detect based on request scheme
        var secureFlag = isSecure ? "; secure" : "";
        
        _logger.LogInformation("Setting cookies - Domain: {Domain}, Secure: {IsSecure}, Scheme: {Scheme}", 
            cookieDomain, isSecure, Request.Scheme);

        // Set access token cookie
        if (!string.IsNullOrEmpty(tokenBundle.AccessToken))
        {
            var expires = DateTimeOffset.UtcNow.AddSeconds(tokenBundle.Expires);
            var cookieValue = $"{tokenBundle.AccessToken}; expires={expires:ddd, dd MMM yyyy HH:mm:ss} GMT; domain={cookieDomain}; path=/; samesite=lax; httponly{secureFlag}";
            Response.Headers.Append("Set-Cookie", $"access_token={cookieValue}");
            _logger.LogInformation("Set access_token cookie, expires: {Expires}", expires);
        }
        
        // Set refresh token cookie
        if (!string.IsNullOrEmpty(tokenBundle.RefreshToken))
        {
            var expires = DateTimeOffset.UtcNow.AddDays(180);
            var cookieValue = $"{tokenBundle.RefreshToken}; expires={expires:ddd, dd MMM yyyy HH:mm:ss} GMT; domain={cookieDomain}; path=/; samesite=lax; httponly{secureFlag}";
            Response.Headers.Append("Set-Cookie", $"refresh_token={cookieValue}");
            _logger.LogInformation("Set refresh_token cookie, expires: {Expires}", expires);
        }
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
    public async Task<IActionResult> Login(string? returnUrl = null, string? successMessage = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }
        
        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);
        
        if (!string.IsNullOrEmpty(successMessage))
        {
            ViewBag.SuccessMessage = successMessage;
        }
        
        return View();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginInputModel model, string? returnUrl = null)
    {
        Guid? tenantId;
        try
        {
            tenantId = await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }
        
        var safeReturnUrl = GetSafeRedirectUrl(returnUrl);
        ViewBag.ReturnUrl = safeReturnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {
            var tokenBundle = await _authService.Login(model.Email, model.Password, tenantId, model.SiteId);

            if (tokenBundle != null)
            {
                ClearAuthCookies();
                GenerateAuthCookies(tokenBundle);
                
                // For React apps, append tokens to URL fragment
                var redirectUrl = safeReturnUrl;
                if (safeReturnUrl.Contains("ui.myapp.local"))
                {
                    redirectUrl = $"{safeReturnUrl}#access_token={tokenBundle.AccessToken}&refresh_token={tokenBundle.RefreshToken}&expires_in={tokenBundle.Expires}";
                }
                
                _logger.LogInformation("Redirecting to: {RedirectUrl}", redirectUrl);
                return Redirect(redirectUrl);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid Login");
                ViewBag.ReturnUrl = safeReturnUrl;
                return View(model);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login failed for user {Email}", model.Email);
            ModelState.AddModelError(string.Empty, "Invalid Login");
            ViewBag.ReturnUrl = safeReturnUrl;
            return View(model);
        }
    }
    #endregion

    #region Logout
    [HttpGet("logout")]
    public async Task<IActionResult> Logout(string? returnUrl = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        // Clear authentication cookies
        ClearAuthCookies();

        _logger.LogInformation("User logged out successfully");

        // Redirect to safe return URL or default
        var safeReturnUrl = GetSafeRedirectUrl(returnUrl);

        return Redirect(safeReturnUrl);
    }
    #endregion

    #region Register
    [HttpGet("register")]
    public async Task<IActionResult> Register(string? returnUrl = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }
        
        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);
        return View();
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterInputModel model, string? returnUrl = null)
    {
        Guid? tenantId;
        try
        {
            tenantId = await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        var safeReturnUrl = GetSafeRedirectUrl(returnUrl);
        ViewBag.ReturnUrl = safeReturnUrl;

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

            var result = await _authService.Register(user, model.Password, null, tenantId, safeReturnUrl);

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
    public async Task<IActionResult> ForgotPassword(string? returnUrl = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }
        
        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);
        return View();
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordInputModel model, string? returnUrl = null)
    {
        Guid? tenantId;
        try
        {
            tenantId = await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        var safeReturnUrl = GetSafeRedirectUrl(returnUrl);
        ViewBag.ReturnUrl = safeReturnUrl;

        if (!ModelState.IsValid)
        {
            return View(model);
        }

        try
        {

            await _authService.SendPasswordResetAsync(model.Email, null, tenantId, safeReturnUrl);

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
    public async Task<IActionResult> ResetPassword(string? userId = null, string? token = null, string? returnUrl = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);

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
    public async Task<IActionResult> ResetPassword(ResetPasswordInputModel model, string? returnUrl = null)
    {
        Guid? tenantId;
        try
        {
            tenantId = await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);

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
                var safeReturnUrl = GetSafeRedirectUrl(returnUrl);
                return RedirectToAction("Login", new { 
                    successMessage = "Password reset successfully! You can now sign in with your new password.",
                    returnUrl = safeReturnUrl
                });
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
    public async Task<IActionResult> RegisterInvitation(string? email = null, string? token = null, string? invitationId = null, string? returnUrl = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);

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
    public async Task<IActionResult> RegisterInvitation(RegisterInvitationInputModel model, string? returnUrl = null)
    {
        try
        {
            await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }
        
        ViewBag.InvitationEmail = model.Email;
        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);

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
                var safeReturnUrl = GetSafeRedirectUrl(returnUrl);
                return RedirectToAction("Login", new { 
                    successMessage = "Registration successful! You can now sign in with your credentials.",
                    returnUrl = safeReturnUrl != _defaultReturnUrl ? safeReturnUrl : null
                });
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
    public async Task<IActionResult> ConfirmEmail(string? userId = null, string? token = null, string? email = null, string? returnUrl = null)
    {
        Guid? tenantId;
        try
        {
            tenantId = await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        ViewBag.ReturnUrl = GetSafeRedirectUrl(returnUrl);

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
    public async Task<IActionResult> ResendConfirmation(string email, string? returnUrl = null)
    {
        Guid? tenantId;
        try
        {
            tenantId = await ValidateTenantAndSetupBrandingAsync();
        }
        catch (NotFoundException ex)
        {
            return RedirectToAction("TenantError", new { message = ex.Message });
        }

        var safeReturnUrl = GetSafeRedirectUrl(returnUrl);
        ViewBag.ReturnUrl = safeReturnUrl;

        if (string.IsNullOrEmpty(email))
        {
            ModelState.AddModelError(string.Empty, "Email address is required to resend confirmation.");
            return View("ConfirmEmail");
        }

        try
        {

            var result = await _authService.SendEmailConfirmationAsync(email, null, tenantId, safeReturnUrl);

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