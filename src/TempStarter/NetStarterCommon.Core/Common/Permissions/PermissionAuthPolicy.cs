using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace NetStarterCommon.Core.Common.Permissions;

public class PermissionAuthPolicy : IAuthorizationPolicyProvider
{
    private DefaultAuthorizationPolicyProvider FallbackPolicyProvider { get; }

    public PermissionAuthPolicy(IOptions<AuthorizationOptions> options)
    {
        FallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
    }

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        // Expect policy names in the format "Permission:PermissionName"
        if (policyName.StartsWith($"{PermissionConstants.PermissionContext}:"))
        {
            var permissionName = policyName.Substring($"{PermissionConstants.PermissionContext}:".Length);
            var policy = new AuthorizationPolicyBuilder()
                .AddRequirements(new PermissionRequirement(permissionName))
                .Build();
            return Task.FromResult(policy)!;
        }

        return FallbackPolicyProvider.GetPolicyAsync(policyName);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() =>
        FallbackPolicyProvider.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() =>
        FallbackPolicyProvider.GetFallbackPolicyAsync();
}
