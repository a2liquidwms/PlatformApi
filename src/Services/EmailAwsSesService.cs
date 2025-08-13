using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
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
        
        var subject = $"Confirm Your Email Address - {branding.SiteName}";
        var htmlBody = GetEmailConfirmationHtmlTemplate(userName, confirmationUrl, branding);
        var textBody = GetEmailConfirmationTextTemplate(userName, confirmationUrl, branding);

        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
    }

    public async Task<bool> SendPasswordResetAsync(string email, string resetUrl, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var subject = $"Reset Your Password - {branding.SiteName}";
        var htmlBody = GetPasswordResetHtmlTemplate(userName, resetUrl, branding);
        var textBody = GetPasswordResetTextTemplate(userName, resetUrl, branding);

        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
    }

    public async Task<bool> SendWelcomeEmailAsync(string email, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var subject = $"Welcome to {branding.SiteName}!";
        var htmlBody = GetWelcomeHtmlTemplate(userName, branding);
        var textBody = GetWelcomeTextTemplate(userName, branding);

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

    private string GetEmailConfirmationHtmlTemplate(string userName, string confirmationUrl, BrandingContext branding)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <title>Confirm Your Email</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {branding.PrimaryColor}; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background-color: #f9f9f9; }}
        .button {{ display: inline-block; padding: 12px 30px; background-color: {branding.PrimaryColor}; color: white; text-decoration: none; border-radius: 5px; }}
        .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
        .logo {{ max-height: 50px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            {(string.IsNullOrEmpty(branding.LogoPath) ? "" : $@"<img src=""{branding.LogoPath}"" alt=""{branding.SiteName}"" class=""logo"" />")}
            <h1>Confirm Your Email Address</h1>
        </div>
        <div class=""content"">
            <h2>Hello {userName}!</h2>
            <p>Thank you for registering with {branding.SiteName}. To complete your registration, please confirm your email address by clicking the button below:</p>
            <p style=""text-align: center; margin: 30px 0;"">
                <a href=""{confirmationUrl}"" class=""button"">Confirm Email Address</a>
            </p>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style=""word-break: break-all; background-color: #f0f0f0; padding: 10px; border-radius: 3px;"">{confirmationUrl}</p>
            <p>This link will expire in 24 hours for security reasons.</p>
        </div>
        <div class=""footer"">
            <p>If you didn't request this email, please ignore it.</p>
            <p>&copy; {DateTime.UtcNow.Year} {branding.SiteName}</p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetEmailConfirmationTextTemplate(string userName, string confirmationUrl, BrandingContext branding)
    {
        return $@"Hello {userName}!

Thank you for registering with {branding.SiteName}. To complete your registration, please confirm your email address by visiting the following link:

{confirmationUrl}

This link will expire in 24 hours for security reasons.

If you didn't request this email, please ignore it.

Best regards,
{branding.SiteName} Team";
    }

    private string GetPasswordResetHtmlTemplate(string userName, string resetUrl, BrandingContext branding)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <title>Reset Your Password</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {branding.PrimaryColor}; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background-color: #f9f9f9; }}
        .button {{ display: inline-block; padding: 12px 30px; background-color: {branding.PrimaryColor}; color: white; text-decoration: none; border-radius: 5px; }}
        .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
        .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .logo {{ max-height: 50px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            {(string.IsNullOrEmpty(branding.LogoPath) ? "" : $@"<img src=""{branding.LogoPath}"" alt=""{branding.SiteName}"" class=""logo"" />")}
            <h1>Reset Your Password</h1>
        </div>
        <div class=""content"">
            <h2>Hello {userName}!</h2>
            <p>We received a request to reset your password for your {branding.SiteName} account. If you made this request, click the button below to reset your password:</p>
            <p style=""text-align: center; margin: 30px 0;"">
                <a href=""{resetUrl}"" class=""button"">Reset Password</a>
            </p>
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style=""word-break: break-all; background-color: #f0f0f0; padding: 10px; border-radius: 3px;"">{resetUrl}</p>
            <div class=""warning"">
                <strong>Security Notice:</strong> This link will expire in 1 hour for security reasons. If you didn't request this password reset, please ignore this email and your password will remain unchanged.
            </div>
        </div>
        <div class=""footer"">
            <p>If you have any concerns about your account security, please contact our support team.</p>
            <p>&copy; {DateTime.UtcNow.Year} {branding.SiteName}</p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetPasswordResetTextTemplate(string userName, string resetUrl, BrandingContext branding)
    {
        return $@"Hello {userName}!

We received a request to reset your password for your {branding.SiteName} account. If you made this request, visit the following link to reset your password:

{resetUrl}

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, please ignore this email and your password will remain unchanged.

Best regards,
{branding.SiteName} Team";
    }

    private string GetWelcomeHtmlTemplate(string userName, BrandingContext branding)
    {
        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <title>Welcome to {branding.SiteName}!</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {branding.PrimaryColor}; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 30px; background-color: #f9f9f9; }}
        .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #666; }}
        .logo {{ max-height: 50px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            {(string.IsNullOrEmpty(branding.LogoPath) ? "" : $@"<img src=""{branding.LogoPath}"" alt=""{branding.SiteName}"" class=""logo"" />")}
            <h1>Welcome to {branding.SiteName}!</h1>
        </div>
        <div class=""content"">
            <h2>Hello {userName}!</h2>
            <p>Your email has been successfully confirmed and your {branding.SiteName} account is now active.</p>
            <p>You can now log in and start using all the features available to you.</p>
            <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
        </div>
        <div class=""footer"">
            <p>Thank you for choosing {branding.SiteName}!</p>
            <p>&copy; {DateTime.UtcNow.Year} {branding.SiteName}</p>
        </div>
    </div>
</body>
</html>";
    }

    private string GetWelcomeTextTemplate(string userName, BrandingContext branding)
    {
        return $@"Hello {userName}!

Welcome to {branding.SiteName}! Your email has been successfully confirmed and your account is now active.

You can now log in and start using all the features available to you.

If you have any questions or need assistance, please don't hesitate to contact our support team.

Thank you for choosing {branding.SiteName}!

Best regards,
{branding.SiteName} Team";
    }
    
    public async Task<bool> SendTenantInvitationEmailAsync(string email, string invitationUrl, string userName, BrandingContext? branding = null)
    {
        branding ??= await _brandingService.GetDefaultBrandingContextAsync();
        
        var subject = $"You're Invited to Join {branding?.SiteName ?? "RedClay"}";
        var htmlBody = GetTenantInvitationHtmlTemplate(userName, invitationUrl, branding);
        var textBody = GetTenantInvitationTextTemplate(userName, invitationUrl, branding);
        
        return await SendEmailAsync(email, subject, htmlBody, textBody, branding);
    }
    
    private string GetTenantInvitationHtmlTemplate(string userName, string invitationUrl, BrandingContext? branding)
    {
        return $@"<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>You're Invited!</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: {branding?.PrimaryColor ?? "#007bff"}; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
        .content {{ background-color: #f8f9fa; padding: 30px; border-radius: 0 0 5px 5px; }}
        .button {{ display: inline-block; background-color: {branding?.PrimaryColor ?? "#007bff"}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; font-size: 12px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class='header'>
        <h1>You're Invited!</h1>
    </div>
    <div class='content'>
        <p>Hello {userName}!</p>
        
        <p>You've been invited to join <strong>{branding?.SiteName ?? "RedClay"}</strong>.</p>
        
        <p>To complete your registration and set up your account, please click the button below:</p>
        
        <p style='text-align: center;'>
            <a href='{invitationUrl}' class='button'>Accept Invitation & Register</a>
        </p>
        
        <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
        <p style='word-break: break-all; color: #007bff;'>{invitationUrl}</p>
        
        <p><strong>Important:</strong> This invitation will expire in 7 days for security reasons.</p>
        
        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
        
        <p>Welcome to {branding?.SiteName ?? "RedClay"}!</p>
    </div>
    <div class='footer'>
        <p>Best regards,<br>{branding?.SiteName ?? "RedClay"} Team</p>
        <p>This email was sent to {userName}. If you didn't expect this invitation, you can safely ignore this email.</p>
    </div>
</body>
</html>";
    }
    
    private string GetTenantInvitationTextTemplate(string userName, string invitationUrl, BrandingContext? branding)
    {
        return $@"You're Invited to Join {branding?.SiteName ?? "RedClay"}!

Hello {userName}!

You've been invited to join {branding?.SiteName ?? "RedClay"}. 

To complete your registration and set up your account, please visit:
{invitationUrl}

Important: This invitation will expire in 7 days for security reasons.

If you have any questions or need assistance, please don't hesitate to contact our support team.

Welcome to {branding?.SiteName ?? "RedClay"}!

Best regards,
{branding?.SiteName ?? "RedClay"} Team

This email was sent to {userName}. If you didn't expect this invitation, you can safely ignore this email.";
    }
}