namespace PlatformApi.Models.DTOs;

public class UserInvitationDto
{
    public Guid Id { get; set; }
    
    public required string Email { get; set; }
    
    public Guid TenantId { get; set; }
    
    public string? InvitedRoles { get; set; }
    
    public DateTime ExpiresAt { get; set; }
    
    public DateTime CreateDate { get; set; }
    
    public string? CreatedBy { get; set; }
}