using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PlatformApi.Emails;
using PlatformApi.Models;
using PlatformApi.Services;

namespace PlatformApi.Controllers;
[AllowAnonymous]
[Route("api/v1/email")]
[ApiController]
public class EmailController : ControllerBase
{
    private readonly ILogger<EmailController> _logger;
    private readonly IBrandingService _brandingService;

    public EmailController(
        ILogger<EmailController> logger,
        IBrandingService brandingService)
    {
        _logger = logger;
        _brandingService = brandingService;
    }

    [HttpGet("preview/confirmation")]
    public async Task<IActionResult> PreviewEmailConfirmation(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe",
        [FromQuery] string confirmationUrl = "https://example.com/confirm/abc123")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new EmailConfirmationTemplate(userName, confirmationUrl);

            var html = template.GenerateHtml(branding);
            
            return Ok(new
            {
                Subject = template.GetSubject(branding),
                Html = html,
                Text = template.GenerateText(branding),
                HtmlLength = html.Length
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating email confirmation preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/password-reset")]
    public async Task<IActionResult> PreviewPasswordReset(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe",
        [FromQuery] string resetUrl = "https://example.com/reset/abc123")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new PasswordResetTemplate(userName, resetUrl);

            var html = template.GenerateHtml(branding);
            
            return Ok(new
            {
                Subject = template.GetSubject(branding),
                Html = html,
                Text = template.GenerateText(branding),
                HtmlLength = html.Length
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating password reset preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/welcome")]
    public async Task<IActionResult> PreviewWelcome(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new WelcomeEmailTemplate(userName);

            var html = template.GenerateHtml(branding);
            
            return Ok(new
            {
                Subject = template.GetSubject(branding),
                Html = html,
                Text = template.GenerateText(branding),
                HtmlLength = html.Length
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating welcome email preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/invitation")]
    public async Task<IActionResult> PreviewInvitation(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe",
        [FromQuery] string invitationUrl = "https://example.com/invite/abc123")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new TenantInvitationTemplate(userName, invitationUrl);

            var html = template.GenerateHtml(branding);
            
            return Ok(new
            {
                Subject = template.GetSubject(branding),
                Html = html,
                Text = template.GenerateText(branding),
                HtmlLength = html.Length
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating invitation email preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/confirmation/html")]
    public async Task<IActionResult> PreviewEmailConfirmationHtml(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe",
        [FromQuery] string confirmationUrl = "https://example.com/confirm/abc123")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new EmailConfirmationTemplate(userName, confirmationUrl);
            var html = template.GenerateHtml(branding);

            return Content(html, "text/html");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating email confirmation HTML preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/password-reset/html")]
    public async Task<IActionResult> PreviewPasswordResetHtml(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe",
        [FromQuery] string resetUrl = "https://example.com/reset/abc123")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new PasswordResetTemplate(userName, resetUrl);
            var html = template.GenerateHtml(branding);

            return Content(html, "text/html");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating password reset HTML preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/welcome/html")]
    public async Task<IActionResult> PreviewWelcomeHtml(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new WelcomeEmailTemplate(userName);
            var html = template.GenerateHtml(branding);

            return Content(html, "text/html");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating welcome email HTML preview");
            return StatusCode(500, "Internal server error");
        }
    }

    [HttpGet("preview/invitation/html")]
    public async Task<IActionResult> PreviewInvitationHtml(
        [FromQuery] Guid? tenantId = null,
        [FromQuery] string userName = "John Doe",
        [FromQuery] string invitationUrl = "https://example.com/invite/abc123")
    {
        try
        {
            var branding = tenantId.HasValue 
                ? await _brandingService.GetBrandingContextAsync(tenantId: tenantId.Value)
                : await _brandingService.GetDefaultBrandingContextAsync();

            var template = new TenantInvitationTemplate(userName, invitationUrl);
            var html = template.GenerateHtml(branding);

            return Content(html, "text/html");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating invitation email HTML preview");
            return StatusCode(500, "Internal server error");
        }
    }
}