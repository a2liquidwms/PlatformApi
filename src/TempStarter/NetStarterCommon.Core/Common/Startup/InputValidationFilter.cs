using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace NetStarterCommon.Core.Common.Startup;


public class InputValidationFilter : IActionFilter
{
    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (!context.ModelState.IsValid)
        {
            var errors = context.ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .SelectMany(kvp => kvp.Value?.Errors.Select(e => new
                {
                    Field = kvp.Key,
                    Message = e.ErrorMessage
                }) ?? Enumerable.Empty<object>()) 
                .ToArray();

            context.Result = new BadRequestObjectResult(new
            {
                Message = "Validation Failed",
                Errors = errors
            });
        }
    }

    public void OnActionExecuted(ActionExecutedContext context) { }
}
