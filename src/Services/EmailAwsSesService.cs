using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using PlatformApi.Models;

namespace PlatformApi.Services;

public class EmailAwsSesService : IEmailService
{
    private readonly IAmazonSimpleEmailService _sesClient;
    private readonly ILogger<EmailAwsSesService> _logger;
    private readonly string _fromDomain;
    private readonly string _configSet;
    private readonly bool _isDevModeConsole;

    public EmailAwsSesService(
        IAmazonSimpleEmailService sesClient, 
        ILogger<EmailAwsSesService> logger,
        IConfiguration configuration)
    {
        _sesClient = sesClient;
        _logger = logger;
        _fromDomain = configuration["EMAIL_DOMAIN"] ?? throw new InvalidOperationException("EMAIL_DOMAIN is required");
        _configSet = configuration["EMAIL_CONFIGURATION_SET"] ?? "";
        _isDevModeConsole = bool.Parse(configuration["EMAIL_DEV_MODE_CONSOLE"] ?? "false");
    }

    public async Task<bool> SendEmailAsync(EmailContent content)
    {
        try
        {
            var sourceAddress = string.IsNullOrEmpty(content.Branding.EmailFromName) 
                ? $"no-reply@{_fromDomain}"
                : $"{content.Branding.EmailFromName} <no-reply@{_fromDomain}>";

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
                    content.ToEmail, sourceAddress, content.Subject, content.Branding.SiteName, _configSet, 
                    content.HtmlBody ?? "[No HTML Body]", content.TextBody ?? "[No Text Body]");
                
                return true;
            }
          
            var request = new SendEmailRequest
            {
                Source = sourceAddress,
                Destination = new Destination
                {
                    ToAddresses = new List<string> { content.ToEmail }
                },
                Message = new Message
                {
                    Subject = new Content(content.Subject),
                    Body = new Body()
                }
            };

            if (!string.IsNullOrEmpty(_configSet))
            {
                request.ConfigurationSetName = _configSet;
            }

            if (!string.IsNullOrEmpty(content.HtmlBody))
            {
                request.Message.Body.Html = new Content
                {
                    Charset = "UTF-8",
                    Data = content.HtmlBody
                };
            }

            if (!string.IsNullOrEmpty(content.TextBody))
            {
                request.Message.Body.Text = new Content
                {
                    Charset = "UTF-8",
                    Data = content.TextBody
                };
            }
            
            var response = await _sesClient.SendEmailAsync(request);
            
            _logger.LogInformation("Email sent successfully. MessageId: {MessageId}, To: {ToEmail}, Branding: {SiteName}", 
                response.MessageId, content.ToEmail, content.Branding.SiteName);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {ToEmail}. Subject: {Subject}", content.ToEmail, content.Subject);
            return false;
        }
    }
}