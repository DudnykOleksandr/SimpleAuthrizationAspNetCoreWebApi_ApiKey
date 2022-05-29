using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SimpleAuthrizationAspNetCoreWebApi_ApiKey
{
    public class ApiKeyAuthNOptions : AuthenticationSchemeOptions
    {
        public string ApiKeyValue { get; set; }

        public string KeyParameterOrHeaderName { get; set; }
    }

    public static class ApiKeyAuthNDefaults
    {
        public const string SchemaName = "ApiKey";
        public const string KeyName = "X-Api-Key";
    }

    public class ApiKeyAuthN : AuthenticationHandler<ApiKeyAuthNOptions>
    {
        public ApiKeyAuthN(
            IOptionsMonitor<ApiKeyAuthNOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var apiKey = ParseApiKey(); // handles parsing QueryString

            if (string.IsNullOrEmpty(apiKey)) //no key was provided - return NoResult
                return Task.FromResult(AuthenticateResult.NoResult());

            if (string.Compare(apiKey, Options.ApiKeyValue, StringComparison.Ordinal) == 0)
            {
                var principal = BuildPrincipal(Scheme.Name, Options.ApiKeyValue, Options.ClaimsIssuer ?? "ApiKeyValue");

                return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name))); //Success. Key matched
            }

            return Task.FromResult(AuthenticateResult.Fail($"Invalid API Key provided.")); //Wrong key was provided
        }

        protected string ParseApiKey()
        {
            if (Request.Headers.TryGetValue(Options.KeyParameterOrHeaderName, out var value))
                return value.FirstOrDefault();

            if (Request.Query.TryGetValue(Options.KeyParameterOrHeaderName, out value))
                return value.FirstOrDefault();

            return string.Empty;
        }

        static ClaimsPrincipal BuildPrincipal(
            string schemeName,
            string name,
            string issuer,
            params Claim[] claims)
        {
            var identity = new ClaimsIdentity(schemeName);

            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, name, ClaimValueTypes.String, issuer));
            identity.AddClaim(new Claim(ClaimTypes.Name, name, ClaimValueTypes.String, issuer));
            identity.AddClaim(new Claim(ClaimTypes.Role, "admin", ClaimValueTypes.String, issuer));

            identity.AddClaims(claims);

            var principal = new ClaimsPrincipal(identity);
            return principal;
        }
    }
}
