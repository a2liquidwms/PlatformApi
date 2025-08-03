namespace PlatformApi.Models.DTOs;

public class UserProfileDto
{
    public required string Id { get; set; }
    public required string Email { get; set; }
    public string? UserName { get; set; }
    public bool IsEmailConfirmed { get; set; }
}