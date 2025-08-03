namespace PlatformApi.Models.DTOs;

public class RegisterViaInvitationRequest
{
    public required string Email { get; set; }
    
    public required string Password { get; set; }
    
    public required string InvitationToken { get; set; }
}