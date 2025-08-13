using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace PlatformApi.Common.Startup;


public class InputValidationFilter : IActionFilter
{
    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (!context.ModelState.IsValid)
        {
            // Check if this is an MVC controller (inherits from Controller)
            // vs API controller (inherits from ControllerBase only)
            var controllerType = context.Controller.GetType();
            var isMvcController = typeof(Controller).IsAssignableFrom(controllerType);
            
            // Only apply JSON response behavior to API controllers
            // Let MVC controllers handle validation naturally with ModelState.IsValid checks
            if (!isMvcController)
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
    }

    public void OnActionExecuted(ActionExecutedContext context) { }
}
