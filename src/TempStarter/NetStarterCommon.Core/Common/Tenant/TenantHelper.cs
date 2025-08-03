using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NetStarterCommon.Core.Common.Constants;

namespace NetStarterCommon.Core.Common.Tenant;

public class TenantHelper
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<TenantHelper> _logger;

    public TenantHelper(IHttpContextAccessor httpContextAccessor, ILogger<TenantHelper> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public Guid GetTenantId()
    {
        Guid tenantId = default;

        if (_httpContextAccessor.HttpContext != null &&
            _httpContextAccessor.HttpContext.Items.TryGetValue(CommonConstants.TenantHttpContext, out var tIdObj))
        {
            if (tIdObj is Guid guidValue)
            {
                tenantId = guidValue;
            }
            else if (tIdObj is string tIdString)
            {
                if (!Guid.TryParse(tIdString, out var parsedTenantId))
                {
                    _logger.LogWarning("Invalid Tenant ID format in Context.Items: {TenantId}", tIdString);
                    throw new InvalidDataException("Invalid Tenant ID format in Context.Items");
                }

                tenantId = parsedTenantId;
            }
            else
            {
                _logger.LogWarning("Unexpected Tenant ID type in Context.Items: {Type}",
                    tIdObj?.GetType().Name ?? "null");
                throw new InvalidDataException("Tenant ID not valid");
            }
        }

        return tenantId;
    }
}