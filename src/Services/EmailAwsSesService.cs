using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using PlatformApi.Emails;
using PlatformApi.Models;

namespace PlatformApi.Services;

public class EmailAwsSesService : IEmailService
{
    private readonly IAmazonSimpleEmailService _sesClient;
    private readonly ILogger<EmailAwsSesService> _logger;
    private readonly IBrandingService _brandingService;
    private readonly string _fromDomain;
    private readonly string _configSet;
    private readonly bool _isDevModeConsole;

    public EmailAwsSesService(
        IAmazonSimpleEmailService sesClient, 
        ILogger<EmailAwsSesService> logger, 
        IBrandingService brandingService,
        IConfiguration configuration)
    {
        _sesClient = sesClient;
        _logger = logger;
        _brandingService = brandingService;
        _fromDomain = configuration["EMAIL_DOMAIN"] ?? throw new InvalidOperationException("EMAIL_DOMAIN is required");
        _configSet = configuration["EMAIL_CONFIGURATION_SET"] ?? "";
        _isDevModeConsole = bool.Parse(configuration["EMAIL_DEV_MODE_CONSOLE"] ?? "false");
    }

    public async Task<bool> SendEmailConfirmationAsync(string email, string confirmationUrl, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var template = new EmailConfirmationTemplate(userName, confirmationUrl);
        var subject = template.GetSubject(branding);
        var htmlBody = template.GenerateHtml(branding);
        var textBody = template.GenerateText(branding);

        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
    }

    public async Task<bool> SendPasswordResetAsync(string email, string resetUrl, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var template = new PasswordResetTemplate(userName, resetUrl);
        var subject = template.GetSubject(branding);
        var htmlBody = template.GenerateHtml(branding);
        var textBody = template.GenerateText(branding);

        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
    }

    public async Task<bool> SendWelcomeEmailAsync(string email, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var template = new WelcomeEmailTemplate(userName);
        var subject = template.GetSubject(branding);
        var htmlBody = template.GenerateHtml(branding);
        var textBody = template.GenerateText(branding);

        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
    }

    public async Task<bool> SendTenantInvitationEmailAsync(string email, string invitationUrl, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var template = new TenantInvitationTemplate(userName, invitationUrl);
        var subject = template.GetSubject(branding);
        var htmlBody = template.GenerateHtml(branding);
        var textBody = template.GenerateText(branding);
        
        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
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