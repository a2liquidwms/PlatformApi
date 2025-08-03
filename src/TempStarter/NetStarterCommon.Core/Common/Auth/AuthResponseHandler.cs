using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace NetStarterCommon.Core.Common.Auth;

public class AuthResponseHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new AuthorizationMiddlewareResultHandler();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Challenged)
        {
            // e.g. return 401 logic here, or let the default handler take over
            await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
        }
        else if (authorizeResult.Forbidden && authorizeResult.AuthorizationFailure?.FailureReasons?.Any() == true)
        {
            // Collect reasons and write them into the response
            var reasons = authorizeResult.AuthorizationFailure.FailureReasons.Select(r => r.Message);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Forbidden",
                details = reasons
            });
        }
        else
        {
            // Fallback to the default handler (which typically returns 403)
            await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
        }
    }
}