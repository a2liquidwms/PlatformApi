namespace PlatformApi.Common.Auth;

public class CommonRolesPermission
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public List<CommonPermission>? Permissions { get; set; }
}