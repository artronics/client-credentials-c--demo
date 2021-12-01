using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

class Program
{
    static void Main(string[] args)
    {
        string token = GetToken();
    }

    static string GetToken()
    {
        string authUrl = "https://internal-dev.api.service.nhs.uk/oauth2";
        string aud = $"{authUrl}/token";
        string tokenEndpoint = $"{authUrl}/token";

        string clientId = "{your-client-id}";

        var certPath = "{path-to-certification.pfx}";
        var cert = new X509Certificate2(certPath);

        // create client_assertion JWT token
        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            clientId,
            aud,
            new List<Claim>
            {
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim(JwtClaimTypes.Subject, clientId),
            },
            now,
            now.AddMinutes(1),
            new SigningCredentials(
                new X509SecurityKey(cert, "{kid-value}"),
                SecurityAlgorithms.RsaSha512
            )
        );

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenString = tokenHandler.WriteToken(token);

        var client = new HttpClient();
        // token request - note there's no client_secret but a client_assertion which contains the token above
        var requestBody = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            {"client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
            {"client_assertion", tokenString},
            {"grant_type", "client_credentials"},
        });

        HttpRequestMessage tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        tokenRequest.Content = requestBody;

        var responseMessage = client.SendAsync(tokenRequest).Result;

        return responseMessage.Content.ReadAsStringAsync().Result;
    }
}
