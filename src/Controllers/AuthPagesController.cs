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
        return _configuration["AUTH_COOKIE_DOMAIN"] ?? "";
    }

    /// <summary>
    /// Detects if the current request is from Safari browser
    /// </summary>
    private bool IsSafariBrowser()
    {
        var userAgent = Request.Headers.UserAgent.ToString();
        return userAgent.Contains("Safari") && !userAgent.Contains("Chrome") && !userAgent.Contains("Chromium");
    }

    /// <summary>
    /// Detects if the current request is to localhost
    /// </summary>
    private bool IsLocalhost()
    {
        var host = Request.Host.Host.ToLower();
        var isLocal = host == "localhost" || host == "127.0.0.1" || host.EndsWith(".myapp.local") || host.EndsWith("myapp.local");
        _logger.LogDebug("IsLocalhost check - Host: '{Host}', IsLocal: {IsLocal}", host, isLocal);
        return isLocal;
    }
    
    private string GetLocalhostDomain()
    {
        var host = Request.Host.Host.ToLower();
        if (host.EndsWith(".myapp.local"))
        {
            return ".myapp.local"; // Allow cross-subdomain sharing on .myapp.local
        }
        if (host.EndsWith(".localhost"))
        {
            return ".localhost"; // Allow cross-subdomain sharing on .localhost
        }
        return ""; // No domain for regular localhost
    }

    /// <summary>
    /// Determines if we're running in development environment
    /// </summary>
    private bool IsDevelopment()
    {
        return _configuration["ASPNETCORE_ENVIRONMENT"] == "Development";
    }

    /// <summary>
    /// Creates Safari-compatible cookie options for the current environment
    /// </summary>
    private CookieOptions CreateSafariCompatibleCookieOptions(string? cookieDomain, bool isRefreshToken = false)
    {
        var isSafari = IsSafariBrowser();
        var isLocalhost = IsLocalhost();
        var isDevelopment = IsDevelopment();
        
        _logger.LogInformation("Cookie Debug - Safari: {IsSafari}, Localhost: {IsLocalhost}, Host: {Host}, Domain: {Domain}, UserAgent: {UserAgent}", 
            isSafari, isLocalhost, Request.Host.Host, cookieDomain ?? "null", Request.Headers.UserAgent.ToString());
        
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Path = "/"
        };

        // Local development (localhost or .myapp.local): Configure for subdomain sharing
        if (isLocalhost || (!string.IsNullOrEmpty(cookieDomain) && cookieDomain.Contains("myapp.local")))
        {
            var localhostDomain = GetLocalhostDomain();
            cookieOptions.SameSite = SameSiteMode.Lax;
            cookieOptions.Secure = false;
            
            if (!string.IsNullOrEmpty(localhostDomain))
            {
                cookieOptions.Domain = localhostDomain; // Set domain for subdomain sharing
            }
            
            _logger.LogDebug("Using localhost cookie configuration: SameSite=Lax, Secure=false, Domain={Domain}", 
                localhostDomain ?? "null");
        }
        // Production or non-Safari: Use standard configuration
        else
        {
            // Safari needs SameSite=None for cross-domain cookies
            if (isSafari && !string.IsNullOrEmpty(cookieDomain))
            {
                cookieOptions.SameSite = SameSiteMode.None;
                cookieOptions.Secure = true; // Required with SameSite=None
                cookieOptions.Domain = cookieDomain;
                _logger.LogDebug("Using Safari cross-domain cookie configuration: SameSite=None, Secure=true, Domain={Domain}", cookieDomain);
            }
            else
            {
                cookieOptions.SameSite = SameSiteMode.Lax;
                cookieOptions.Secure = false;
                
                // Set domain for cross-subdomain sharing (only if not localhost)
                if (!string.IsNullOrEmpty(cookieDomain))
                {
                    cookieOptions.Domain = cookieDomain;
                }
            }
            
            _logger.LogDebug("Using standard cookie configuration: SameSite=Lax, Secure={Secure}, Domain={Domain}", 
                cookieOptions.Secure, cookieDomain ?? "null");
        }

        // Set expiration
        if (isRefreshToken)
        {
            // Refresh tokens get longer expiration (handled by caller)
        }
        
        return cookieOptions;
    }

    /// <summary>
    /// Resolves the effective return URL using fallback hierarchy:
    /// 1. Provided returnUrl (if valid)
    /// 2. System default from environment variable
    /// 3. Root fallback ("/")
    /// </summary>
    private string GetEffectiveReturnUrl(string? providedReturnUrl, Guid? tenantId = null)
    {
        // 1. Use provided returnUrl if valid
        if (!string.IsNullOrEmpty(providedReturnUrl) && IsValidReturnUrl(providedReturnUrl, tenantId))
        {
            return providedReturnUrl;
        }

        // 2. Fall back to system default
        var defaultReturnUrl = _configuration["DEFAULT_RETURN_URL"];
        if (!string.IsNullOrEmpty(defaultReturnUrl) && IsValidReturnUrl(defaultReturnUrl, tenantId))
        {
            return defaultReturnUrl;
        }

        // 3. Final fallback to root
        return "/";
    }

    /// <summary>
    /// Validates if a return URL is safe to redirect to.
    /// Supports local URLs, configured default URL, and tenant-specific URLs.
    /// </summary>
    private bool IsValidReturnUrl(string? returnUrl, Guid? tenantId = null)
    {
        if (string.IsNullOrEmpty(returnUrl)) return false;

        try
        {
            // Allow local URLs (development)
            if (Url.IsLocalUrl(returnUrl)) return true;

            // Allow configured default URL
            var defaultUrl = _configuration["DEFAULT_RETURN_URL"];
            if (!string.IsNullOrEmpty(defaultUrl) && returnUrl.Equals(defaultUrl, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Allow tenant-specific URLs if we have tenant context
            if (tenantId.HasValue && IsValidTenantUrl(returnUrl, tenantId.Value))
            {
                return true;
            }

            // Allow configured auth domain pattern
            var authBaseDomain = _configuration["AUTH_BASE_DOMAIN"];
            if (!string.IsNullOrEmpty(authBaseDomain))
            {
                var uri = new Uri(returnUrl);
                return uri.Host.Contains(authBaseDomain.Split(':')[0]);
            }

            return false;
        }
        catch (UriFormatException)
        {
            // Invalid URI format
            return false;
        }
    }

    /// <summary>
    /// Validates if a URL belongs to a specific tenant's subdomain.
    /// </summary>
    private bool IsValidTenantUrl(string returnUrl, Guid tenantId)
    {
        try
        {
            var uri = new Uri(returnUrl);
            var authBaseDomain = _configuration["AUTH_BASE_DOMAIN"];
            
            if (string.IsNullOrEmpty(authBaseDomain)) return false;

            // For development (localhost), allow any localhost URL
            if (authBaseDomain.Contains("localhost"))
            {
                return uri.Host.Contains("localhost");
            }

            // For production, validate tenant subdomain pattern
            // Expected format: https://tenant1.ui.domain.com (where AUTH_BASE_DOMAIN might be api.domain.com)
            var baseDomain = authBaseDomain.Split(':')[0];
            return uri.Host.EndsWith($".{baseDomain}") || uri.Host.Equals(baseDomain, StringComparison.OrdinalIgnoreCase);
        }
        catch (UriFormatException)
        {
            return false;
        }
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
    public async Task<IActionResult> Login(string? returnUrl = null, string? successMessage = null)
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.ReturnUrl = returnUrl;
        
        if (!string.IsNullOrEmpty(successMessage))
        {
            ViewBag.SuccessMessage = successMessage;
        }
        
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
                var cookieDomain = GetCookieDomain();
                var cookieOptions = CreateSafariCompatibleCookieOptions(cookieDomain);
                
                // Set access token cookie
                if (!string.IsNullOrEmpty(tokenBundle.AccessToken))
                {
                    cookieOptions.Expires = DateTimeOffset.UtcNow.AddSeconds(tokenBundle.Expires);
                    Response.Cookies.Append("access_token", tokenBundle.AccessToken, cookieOptions);
                    _logger.LogInformation("Set access_token cookie. Domain: {Domain}, SameSite: {SameSite}, Secure: {Secure}", 
                        cookieOptions.Domain ?? "null", cookieOptions.SameSite, cookieOptions.Secure);
                }
                
                // Set refresh token cookie with longer expiration
                if (!string.IsNullOrEmpty(tokenBundle.RefreshToken))
                {
                    var refreshTokenDays = int.Parse(_configuration["AUTH_REFRESH_TOKEN_DAYS"] ?? "180");
                    cookieOptions.Expires = DateTimeOffset.UtcNow.AddDays(refreshTokenDays);

                    Response.Cookies.Append("refresh_token", tokenBundle.RefreshToken, cookieOptions);
                    _logger.LogInformation("Set refresh_token cookie. Domain: {Domain}, SameSite: {SameSite}, Secure: {Secure}, Expires: {Expires}", 
                        cookieOptions.Domain ?? "null", cookieOptions.SameSite, cookieOptions.Secure, cookieOptions.Expires);
                }
                
                // Redirect back to the effective return URL
                var effectiveReturnUrl = GetEffectiveReturnUrl(returnUrl, tenantId);
                if (effectiveReturnUrl != "/")
                {
                    return Redirect(effectiveReturnUrl);
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

    #region Logout
    [HttpGet("logout")]
    public async Task<IActionResult> Logout(string? returnUrl = null)
    {
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        // Clear authentication cookies with Safari compatibility
        var cookieDomain = GetCookieDomain();
        var clearCookieOptions = CreateSafariCompatibleCookieOptions(cookieDomain);
        clearCookieOptions.Expires = DateTimeOffset.UtcNow.AddDays(-1); // Expire in the past to delete

        // Clear both access and refresh tokens
        Response.Cookies.Append("access_token", "", clearCookieOptions);
        Response.Cookies.Append("refresh_token", "", clearCookieOptions);

        _logger.LogInformation("Clearing cookies for user logout. Browser: {UserAgent}, Domain: {Domain}, SameSite: {SameSite}, Secure: {Secure}", 
            Request.Headers.UserAgent.ToString(), clearCookieOptions.Domain ?? "null", clearCookieOptions.SameSite, clearCookieOptions.Secure);

        _logger.LogInformation("User logged out successfully");

        // Redirect to effective return URL or default
        var effectiveReturnUrl = GetEffectiveReturnUrl(returnUrl, tenantId);
        
        // If returning to root, redirect to login instead
        if (effectiveReturnUrl == "/")
        {
            return RedirectToAction("Login", new { successMessage = "You have been logged out successfully." });
        }

        return Redirect(effectiveReturnUrl);
    }
    #endregion

    #region Register
    [HttpGet("register")]
    public async Task<IActionResult> Register(string? returnUrl = null)
    {
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.ReturnUrl = returnUrl;
        return View();
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterInputModel model, string? returnUrl = null)
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
            var user = new AuthUser 
            { 
                UserName = model.Email, 
                Email = model.Email 
            };

            var result = await _authService.Register(user, model.Password, null, tenantId, returnUrl);

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
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.ReturnUrl = returnUrl;
        return View();
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordInputModel model, string? returnUrl = null)
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

            await _authService.SendPasswordResetAsync(model.Email, null, tenantId, returnUrl);

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
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        ViewBag.ReturnUrl = returnUrl;

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
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        ViewBag.ReturnUrl = returnUrl;

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
                var effectiveReturnUrl = GetEffectiveReturnUrl(returnUrl, tenantId);
                return RedirectToAction("Login", new { 
                    successMessage = "Password reset successfully! You can now sign in with your new password.",
                    returnUrl = effectiveReturnUrl != "/" ? effectiveReturnUrl : null
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
        var (errorResult, _) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        ViewBag.ReturnUrl = returnUrl;

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
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;
        
        ViewBag.InvitationEmail = model.Email;
        ViewBag.ReturnUrl = returnUrl;

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
                var effectiveReturnUrl = GetEffectiveReturnUrl(returnUrl, tenantId);
                return RedirectToAction("Login", new { 
                    successMessage = "Registration successful! You can now sign in with your credentials.",
                    returnUrl = effectiveReturnUrl != "/" ? effectiveReturnUrl : null
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
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        ViewBag.ReturnUrl = returnUrl;

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
        var (errorResult, tenantId) = await ValidateTenantAndSetupBrandingAsync();
        if (errorResult != null) return errorResult;

        ViewBag.ReturnUrl = returnUrl;

        if (string.IsNullOrEmpty(email))
        {
            ModelState.AddModelError(string.Empty, "Email address is required to resend confirmation.");
            return View("ConfirmEmail");
        }

        try
        {

            var result = await _authService.SendEmailConfirmationAsync(email, null, tenantId, returnUrl);

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