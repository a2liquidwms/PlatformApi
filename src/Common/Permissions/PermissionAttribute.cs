using Microsoft.AspNetCore.Authorization;

namespace PlatformApi.Common.Permissions;
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public class RequirePermissionAttribute : AuthorizeAttribute
{
    public RequirePermissionAttribute(string permission)
    {
        Policy = $"{PermissionConstants.PermissionContext}:{permission}";
    }
}