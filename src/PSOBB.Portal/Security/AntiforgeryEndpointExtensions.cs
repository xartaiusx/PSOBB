using Microsoft.AspNetCore.Antiforgery;

namespace PSOBB.Portal.Security;

public static class AntiforgeryEndpointExtensions
{
    public static RouteHandlerBuilder RequireAntiforgery(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter(async (context, next) =>
        {
            var antiforgery = context.HttpContext.RequestServices
                .GetRequiredService<IAntiforgery>();
            try
            {
                await antiforgery.ValidateRequestAsync(context.HttpContext);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest(new { error = "request_rejected" });
            }

            return await next(context);
        });
}
