using PlatformApi.Models;

namespace PlatformApi.Services;

public interface IEmailService 
{
    Task<bool> SendEmailAsync(EmailContent content);
}