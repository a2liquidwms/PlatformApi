namespace NetStarterCommon.Core.Common.Models;

public class CommonRolesPermission
{
    public string? CreateDate { get; set; }
    public string? CreatedBy { get; set; }
    public string? LastModifiedDate { get; set; }
    public string? LastModifiedBy { get; set; }
    public string? ModifiedSource { get; set; }
    public string? Id { get; set; }
    public string? Name { get; set; }
    public List<CommonPermission>? Permissions { get; set; }
}