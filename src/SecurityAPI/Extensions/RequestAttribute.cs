using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using System.Net;

namespace SecurityAPI.Extensions;

/*
IP Based Request Limit Action 
We can limit clients to a number of requests 
within the specified time span to prevent malicious bot attacks
*/

[AttributeUsage(AttributeTargets.Method)]
public class RequestLimitAttribute : ActionFilterAttribute
{
    private static MemoryCache MemoryCache { get; } = new MemoryCache(new MemoryCacheOptions());
    public RequestLimitAttribute(string name) { Name = name; }
    public string Name { get; }
    public int NoOfRequest { get; set; } = 1;
    public int Seconds { get; set; } = 1;

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var ipAddress = context.HttpContext
            .Request
            .HttpContext
            .Connection
            .RemoteIpAddress;

        var memoryCacheKey = $"{Name}-{ipAddress}";

        MemoryCache.TryGetValue(memoryCacheKey, out int prevReqCount);

        if (prevReqCount >= NoOfRequest)
        {
            context.Result = new ContentResult
            {
                Content = $"Request is exceeded. Try again in seconds.",
            };
            context.HttpContext.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
        }
        else
        {
            var cacheEntryOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromSeconds(Seconds));
            MemoryCache.Set(memoryCacheKey, (prevReqCount + 1), cacheEntryOptions);
        }
    }
}

