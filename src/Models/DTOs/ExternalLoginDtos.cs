namespace PlatformApi.Models.DTOs;

public record ExternalLoginRequest(string Provider, string ProviderKey, string Email);

public record UnlinkProviderRequest(string Provider, string ProviderKey);