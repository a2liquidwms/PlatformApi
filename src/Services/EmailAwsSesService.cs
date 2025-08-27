using System.Web;
using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Data;
using PlatformApi.Emails;
using PlatformApi.Models;

namespace PlatformApi.Services;

public class EmailAwsSesService : IEmailService
{
    private readonly IAmazonSimpleEmailService _sesClient;
    private readonly ILogger<EmailAwsSesService> _logger;
    private readonly IBrandingService _brandingService;
    private readonly PlatformDbContext _context;
    private readonly string _fromDomain;
    private readonly string _configSet;
    private readonly bool _isDevModeConsole;

    public EmailAwsSesService(
        IAmazonSimpleEmailService sesClient, 
        ILogger<EmailAwsSesService> logger, 
        IBrandingService brandingService,
        PlatformDbContext context,
        IConfiguration configuration)
    {
        _sesClient = sesClient;
        _logger = logger;
        _brandingService = brandingService;
        _context = context;
        _fromDomain = configuration["EMAIL_DOMAIN"] ?? throw new InvalidOperationException("EMAIL_DOMAIN is required");
        _configSet = configuration["EMAIL_CONFIGURATION_SET"] ?? "";
        _isDevModeConsole = bool.Parse(configuration["EMAIL_DEV_MODE_CONSOLE"] ?? "false");
    }

    public async Task<bool> SendEmailConfirmationAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null)
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

            return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email confirmation to {Email}", email);
            return false;
        }
    }

    public async Task<bool> SendPasswordResetAsync(string email, string token, Guid userId, string userName, Guid? tenantId = null, string? returnUrl = null)
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

            return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send password reset to {Email}", email);
            return false;
        }
    }

    public async Task<bool> SendWelcomeEmailAsync(string email, string userName, Guid? tenantId = null)
    {
        try
        {
            // Get branding context
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            
            var template = new WelcomeEmailTemplate(userName);
            var subject = template.GetSubject(branding);
            var htmlBody = template.GenerateHtml(branding);
            var textBody = template.GenerateText(branding);

            return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send welcome email to {Email}", email);
            return false;
        }
    }


    public async Task<bool> SendInvitationEmailAsync(string email, string token, string userName, RoleScope scope, Guid? tenantId = null, Guid? siteId = null)
    {
        try
        {
            // Get branding context based on scope
            var branding = await _brandingService.GetBrandingContextAsync(null, tenantId);
            
            // Generate invitation URL based on scope
            var encodedToken = HttpUtility.UrlEncode(token);
            var invitationUrl = $"{branding.BaseUrl}/accept-invitation?token={encodedToken}";

            EmailTemplateBase template;
            
            switch (scope)
            {
                case RoleScope.Tenant:
                    template = new TenantInvitationTemplate(userName, invitationUrl);
                    break;
                case RoleScope.Site:
                    // Get site name for site invitations
                    string siteName = "Site";
                    if (siteId.HasValue)
                    {
                        var site = await _context.Sites.FirstOrDefaultAsync(s => s.Id == siteId);
                        siteName = site?.Name ?? "Site";
                    }
                    template = new SiteInvitationTemplate(userName, invitationUrl, siteName);
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

            return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send invitation email to {Email} for scope {Scope}", email, scope);
            return false;
        }
    }

    public async Task<bool> SendEmailAsync(string toEmail, string subject, string htmlBody, string? textBody = null, BrandingContext? branding = null)
    {
        try
        {
            branding ??= await _brandingService.GetDefaultBrandingContextAsync();
            
            var sourceAddress = string.IsNullOrEmpty(branding.EmailFromName) 
                ? $"no-reply@{_fromDomain}"
                : $"{branding.EmailFromName} <no-reply@{_fromDomain}>";

            if (_isDevModeConsole)
            {
                _logger.LogInformation(@"
=== EMAIL DEV MODE - CONSOLE OUTPUT ===
To: {ToEmail}
From: {SourceAddress}
Subject: {Subject}
Branding: {SiteName}
Configuration Set: {ConfigSet}

--- HTML BODY ---
{HtmlBody}

--- TEXT BODY ---
{TextBody}

=== END EMAIL DEV MODE OUTPUT ===", 
                    toEmail, sourceAddress, subject, branding.SiteName, _configSet, 
                    htmlBody ?? "[No HTML Body]", textBody ?? "[No Text Body]");
                
                return true;
            }
          
            var request = new SendEmailRequest
            {
                Source = sourceAddress,
                Destination = new Destination
                {
                    ToAddresses = new List<string> { toEmail }
                },
                Message = new Message
                {
                    Subject = new Content(subject),
                    Body = new Body()
                }
            };

            if (!string.IsNullOrEmpty(_configSet))
            {
                request.ConfigurationSetName = _configSet;
            }

            if (!string.IsNullOrEmpty(htmlBody))
            {
                request.Message.Body.Html = new Content
                {
                    Charset = "UTF-8",
                    Data = htmlBody
                };
            }

            if (!string.IsNullOrEmpty(textBody))
            {
                request.Message.Body.Text = new Content
                {
                    Charset = "UTF-8",
                    Data = textBody
                };
            }
            
            var response = await _sesClient.SendEmailAsync(request);
            
            _logger.LogInformation("Email sent successfully. MessageId: {MessageId}, To: {ToEmail}, Branding: {SiteName}", 
                response.MessageId, toEmail, branding.SiteName);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {ToEmail}. Subject: {Subject}", toEmail, subject);
            return false;
        }
    }
}