using System.Web;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Data;
using PlatformApi.Emails;
using PlatformApi.Models;

namespace PlatformApi.Services;

public class EmailContentService : IEmailContentService
{
    private readonly IBrandingService _brandingService;
    private readonly PlatformDbContext _context;
    private readonly ILogger<EmailContentService> _logger;

    public EmailContentService(
        IBrandingService brandingService,
        PlatformDbContext context,
        ILogger<EmailContentService> logger)
    {
        _brandingService = brandingService;
        _context = context;
        _logger = logger;
    }

    public async Task<EmailContent> PrepareEmailConfirmationAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null)
    {
        try
        {
            // Get branding context
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            
            // Generate confirmation URL
            var encodedToken = HttpUtility.UrlEncode(token);
            var encodedUserId = HttpUtility.UrlEncode(userId.ToString());
            var confirmationUrl = $"{branding.BaseUrl}/confirm-email?token={encodedToken}&userId={encodedUserId}";
            
            // Add return URL if provided
            if (!string.IsNullOrEmpty(returnUrl))
            {
                confirmationUrl += $"&returnUrl={HttpUtility.UrlEncode(returnUrl)}";
            }
            
            var template = new EmailConfirmationTemplate(userName, confirmationUrl);
            var subject = template.GetSubject(branding);
            var htmlBody = template.GenerateHtml(branding);
            var textBody = template.GenerateText(branding);

            return new EmailContent
            {
                ToEmail = email,
                Subject = subject,
                HtmlBody = htmlBody,
                TextBody = textBody,
                Branding = branding
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prepare email confirmation content for {Email}", email);
            throw;
        }
    }

    public async Task<EmailContent> PreparePasswordResetAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null)
    {
        try
        {
            // Get branding context
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            
            // Generate reset URL
            var encodedToken = HttpUtility.UrlEncode(token);
            var encodedUserId = HttpUtility.UrlEncode(userId.ToString());
            var resetUrl = $"{branding.BaseUrl}/reset-password?token={encodedToken}&userId={encodedUserId}";
            
            // Add return URL if provided
            if (!string.IsNullOrEmpty(returnUrl))
            {
                resetUrl += $"&returnUrl={HttpUtility.UrlEncode(returnUrl)}";
            }
            
            var template = new PasswordResetTemplate(userName, resetUrl);
            var subject = template.GetSubject(branding);
            var htmlBody = template.GenerateHtml(branding);
            var textBody = template.GenerateText(branding);

            return new EmailContent
            {
                ToEmail = email,
                Subject = subject,
                HtmlBody = htmlBody,
                TextBody = textBody,
                Branding = branding
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prepare password reset content for {Email}", email);
            throw;
        }
    }

    public async Task<EmailContent> PrepareWelcomeEmailAsync(string email, string userName, Guid? tenantId = null)
    {
        try
        {
            // Get branding context
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            
            var template = new WelcomeEmailTemplate(userName);
            var subject = template.GetSubject(branding);
            var htmlBody = template.GenerateHtml(branding);
            var textBody = template.GenerateText(branding);

            return new EmailContent
            {
                ToEmail = email,
                Subject = subject,
                HtmlBody = htmlBody,
                TextBody = textBody,
                Branding = branding
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prepare welcome email content for {Email}", email);
            throw;
        }
    }

    public async Task<EmailContent> PrepareInvitationEmailAsync(string email, string token, string userName, RoleScope scope, Guid? tenantId = null, Guid? siteId = null)
    {
        try
        {
            // Get branding context based on scope
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            
            // Generate invitation URL based on scope
            var encodedToken = HttpUtility.UrlEncode(token);
            var encodedEmail = HttpUtility.UrlEncode(email);
            var invitationUrl = $"{branding.BaseUrl}/register-invitation?token={encodedToken}&email={encodedEmail}";

            EmailTemplateBase template;
            
            switch (scope)
            {
                case RoleScope.Tenant:
                case RoleScope.Site:
                    template = new TenantInvitationTemplate(userName, invitationUrl);
                    break;
                case RoleScope.Internal:
                    template = new InternalInvitationTemplate(userName, invitationUrl);
                    break;
                default:
                    throw new ArgumentException($"Unsupported role scope: {scope}");
            }

            var subject = template.GetSubject(branding);
            var htmlBody = template.GenerateHtml(branding);
            var textBody = template.GenerateText(branding);

            return new EmailContent
            {
                ToEmail = email,
                Subject = subject,
                HtmlBody = htmlBody,
                TextBody = textBody,
                Branding = branding
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to prepare invitation email content for {Email} with scope {Scope}", email, scope);
            throw;
        }
    }
}