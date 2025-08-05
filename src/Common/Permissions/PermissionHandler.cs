using Microsoft.AspNetCore.Authorization;
using NetStarterCommon.Core.Common.Models;

namespace PlatformApi.Common.Permissions
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission { get; }

        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }
    
    public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public PermissionHandler(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            // Ensure the user is authenticated
            if (context.User.Identity?.IsAuthenticated != true)
            {
                context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
                return Task.CompletedTask;
            }
            // Retrieve permissions from HttpContext.Items (set in middleware)
            if (_httpContextAccessor.HttpContext?.Items.TryGetValue(PermissionConstants.PermissionContext,
                    out var permissionsObj) == true 
                && permissionsObj is List<CommonPermission> permissions 
                && permissions.Any(p => p.Code == requirement.Permission))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail(new AuthorizationFailureReason(this, "Access Denied"));
            }

            return Task.CompletedTask;
        }
    }
}

