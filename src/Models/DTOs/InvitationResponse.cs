namespace PlatformApi.Models.DTOs;

public class InvitationResponse
{
    public bool Success { get; set; }
    
    public required string Message { get; set; }
    
    public Guid? InvitationId { get; set; }
}