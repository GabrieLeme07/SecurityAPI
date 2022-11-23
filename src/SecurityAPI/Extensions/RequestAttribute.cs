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

/* 
 To protect APIs from abuse and to provide additional
 protection against Cross-Site Request Forgery (CSRF) attacks
 */

[AttributeUsage(AttributeTargets.Method)]
public sealed class RequestCheckAttribute : ActionFilterAttribute
{
    private IConfiguration _configuration;

    public RequestCheckAttribute() { }

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        _configuration = context
            .HttpContext
            .RequestServices
            .GetService(typeof(IConfiguration)) as IConfiguration;

        base.OnActionExecuting(context);

        if (!IsValidRequest(context.HttpContext.Request))
        {
            context.Result = new ContentResult
            {
                Content = $"Invalid header"
            };
            context.HttpContext.Response.StatusCode = (int)HttpStatusCode.ExpectationFailed;
        }
    }

    private bool IsValidRequest(HttpRequest request)
    {
        string referrerURL = "";
        if (request.Headers.ContainsKey("Referer"))
        {
            referrerURL = request.Headers["Referer"];
        }
        if (string.IsNullOrWhiteSpace(referrerURL)) return false;

        //Allows to check customer list
        var urls = _configuration.GetSection("CorsOrigin")
            .Get<string[]>()?
            .Select(url => new Uri(url).Authority)
            .ToList();

        //For swagger test use this
        urls ??= new List<string>();

        //add current host for swagger calls    
        var host = request.Host.Value;
        urls.Add(host);
        bool isValidClient = urls.Contains(new Uri(referrerURL).Authority);
        // comapre with base uri
        return isValidClient;
    }
}

