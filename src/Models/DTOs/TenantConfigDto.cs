namespace PlatformApi.Models.DTOs;

public class TenantConfigDto
{
    public Guid Id { get; set; }

    public required Guid TenantId { get; set; }

    public string? SubDomain { get; set; }

    public string? TenantName { get; set; }

    public string? LogoPath { get; set; }

    public string? PrimaryColor { get; set; }
}