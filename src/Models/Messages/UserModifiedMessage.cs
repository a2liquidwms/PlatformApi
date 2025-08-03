namespace PlatformApi.Models.Messages;

public class UserModifiedMessage
{
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public DateTime ModifiedAt { get; set; } = DateTime.UtcNow;
}