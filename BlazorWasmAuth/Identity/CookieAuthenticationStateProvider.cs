using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using BlazorWasmAuth.Identity.Models;
using System.Text;
using System.Net;
using System.Text.Json.Serialization;

namespace BlazorWasmAuth.Identity
{
    /// <summary>
    /// Handles state for cookie-based auth.
    /// </summary>
    /// <remarks>
    /// Create a new instance of the auth provider.
    /// </remarks>
    /// <param name="httpClientFactory">Factory to retrieve auth client.</param>
    public class CookieAuthenticationStateProvider(IHttpClientFactory httpClientFactory) : AuthenticationStateProvider, IAccountManagement
    {
        /// <summary>
        /// Map the JavaScript-formatted properties to C#-formatted classes.
        /// </summary>
        private readonly JsonSerializerOptions jsonSerializerOptions =
            new()
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            };

        /// <summary>
        /// Special auth client.
        /// </summary>
        private readonly HttpClient httpClient = httpClientFactory.CreateClient("Auth");

        /// <summary>
        /// Authentication state.
        /// </summary>
        private bool authenticated = false;

        /// <summary>
        /// Default principal for anonymous (not authenticated) users.
        /// </summary>
        private readonly ClaimsPrincipal unauthenticated = new(new ClaimsIdentity());

        /// <summary>
        /// Register a new user.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <returns>The result serialized to a <see cref="FormResult"/>.
        /// </returns>
        public async Task<FormResult> RegisterAsync(string email, string password)
        {
            string[] defaultDetail = [ "An unknown error prevented registration from succeeding." ];

            try
            {
                // make the request
                var result = await httpClient.PostAsJsonAsync(
                    "register", new
                    {
                        email,
                        password
                    });

                // successful?
                if (result.IsSuccessStatusCode)
                {
                    return new FormResult { Succeeded = true };
                }

                // body should contain details about why it failed
                var details = await result.Content.ReadAsStringAsync();
                var problemDetails = JsonDocument.Parse(details);
                var errors = new List<string>();
                var errorList = problemDetails.RootElement.GetProperty("errors");

                foreach (var errorEntry in errorList.EnumerateObject())
                {
                    if (errorEntry.Value.ValueKind == JsonValueKind.String)
                    {
                        errors.Add(errorEntry.Value.GetString()!);
                    }
                    else if (errorEntry.Value.ValueKind == JsonValueKind.Array)
                    {
                        errors.AddRange(
                            errorEntry.Value.EnumerateArray().Select(
                                e => e.GetString() ?? string.Empty)
                            .Where(e => !string.IsNullOrEmpty(e)));
                    }
                }

                // return the error list
                return new FormResult
                {
                    Succeeded = false,
                    ErrorList = problemDetails == null ? defaultDetail : [.. errors]
                };
            }
            catch { }

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = defaultDetail
            };
        }

        /// <summary>
        /// User login.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <returns>The result of the login request serialized to a <see cref="FormResult"/>.</returns>
        public async Task<FormResult> LoginAsync(string email, string password)
        {
            try
            {
                // login with cookies
                var result = await httpClient.PostAsJsonAsync(
                    "login?useCookies=true", new
                    {
                        email,
                        password
                    });

                // success?
                if (result.IsSuccessStatusCode)
                {
                    // need to refresh auth state
                    NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());

                    // success!
                    return new FormResult { Succeeded = true };
                }
                else if (result.StatusCode == HttpStatusCode.Unauthorized)
                {
                    var responseJson = await result.Content.ReadAsStringAsync();
                    var response = JsonSerializer.Deserialize<LoginResponse>(
                        responseJson, jsonSerializerOptions);

                    if (response?.Detail == "RequiresTwoFactor")
                    {
                        return new FormResult
                        {
                            Succeeded = false,
                            ErrorList = [ "RequiresTwoFactor" ]
                        };
                    }
                }
            }
            catch { }

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = [ "Invalid email and/or password." ]
            };
        }

        /// <summary>
        /// User login with two-factor authentication.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="twoFactorCode">The user's password.</param>
        /// <returns>The result of the login request serialized to a <see cref="FormResult"/>.</returns>
        public async Task<FormResult> LoginTwoFactorCodeAsync(
            string email, string password, string twoFactorCode)
        {
            try
            {
                // login with cookies
                var result = await httpClient.PostAsJsonAsync(
                    "login?useCookies=true", new
                    {
                        email,
                        password,
                        twoFactorCode
                    });

                // success?
                if (result.IsSuccessStatusCode)
                {
                    // need to refresh auth state
                    NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());

                    // success!
                    return new FormResult { Succeeded = true };
                }
            }
            catch { }

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = [ "Invalid two-factor code." ]
            };
        }

        /// <summary>
        /// Get authentication state.
        /// </summary>
        /// <remarks>
        /// Called by Blazor anytime and authentication-based decision needs to be made, then cached
        /// until the changed state notification is raised.
        /// </remarks>
        /// <returns>The authentication state asynchronous request.</returns>
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            authenticated = false;

            // default to not authenticated
            var user = unauthenticated;

            try
            {
                // the user info endpoint is secured, so if the user isn't
                // logged in this will fail
                var userResponse = await httpClient.GetAsync("manage/info");

                // throw if user info wasn't retrieved
                userResponse.EnsureSuccessStatusCode();

                // user is authenticated,so let's build their authenticated identity
                var userJson = await userResponse.Content.ReadAsStringAsync();
                var userInfo = JsonSerializer.Deserialize<UserInfo>(userJson, 
                    jsonSerializerOptions);

                if (userInfo != null)
                {
                    // in this example app, name and email are the same
                    var claims = new List<Claim>
                    {
                        new(ClaimTypes.Name, userInfo.Email),
                        new(ClaimTypes.Email, userInfo.Email),
                    };

                    // add any additional claims
                    claims.AddRange(
                        userInfo.Claims.Where(c => c.Key != ClaimTypes.Name && 
                            c.Key != ClaimTypes.Email)
                            .Select(c => new Claim(c.Key, c.Value)));

                    // request the roles endpoint for the user's roles
                    var rolesResponse = await httpClient.GetAsync("roles");

                    // throw if request fails
                    rolesResponse.EnsureSuccessStatusCode();

                    // read the response into a string
                    var rolesJson = await rolesResponse.Content.ReadAsStringAsync();

                    // deserialize the roles string into an array
                    var roles = JsonSerializer.Deserialize<RoleClaim[]>(rolesJson, 
                        jsonSerializerOptions);

                    // add any roles to the claims collection
                    if (roles?.Length > 0)
                    {
                        foreach (var role in roles)
                        {
                            if (!string.IsNullOrEmpty(role.Type) && 
                                !string.IsNullOrEmpty(role.Value))
                            {
                                claims.Add(new Claim(role.Type, role.Value, 
                                    role.ValueType, role.Issuer, role.OriginalIssuer));
                            }
                        }
                    }

                    // set the principal
                    var id = new ClaimsIdentity(claims, 
                        nameof(CookieAuthenticationStateProvider));
                    user = new ClaimsPrincipal(id);
                    authenticated = true;
                }
            }
            catch { }

            // return the state
            return new AuthenticationState(user);
        }

        public async Task LogoutAsync()
        {
            const string Empty = "{}";
            var emptyContent = new StringContent(Empty, Encoding.UTF8, 
                "application/json");
            await httpClient.PostAsync("logout", emptyContent);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        /// <summary>
        /// Authentication check.
        /// </summary>
        /// <returns>The result of the request serialized to <see cref="bool"/>.</returns>
        public async Task<bool> CheckAuthenticatedAsync()
        {
            await GetAuthenticationStateAsync();
            return authenticated;
        }

        /// <summary>
        /// Begin the password recovery process by issuing a POST request to the /forgotPassword endpoint.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <returns>A <see cref="bool"/> indicating success or failure.</returns>
        public async Task<bool> ForgotPasswordAsync(string email)
        {
            try
            {
                // make the request
                var result = await httpClient.PostAsJsonAsync(
                    "forgotPassword", new
                    {
                        email
                    });

                // successful?
                if (result.IsSuccessStatusCode)
                {
                    return true;
                }
            }
            catch { }

            // unknown error
            return false;
        }

        /// <summary>
        /// Reset the user's password.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="resetCode">The user's reset code.</param>
        /// <param name="newPassword">The user's new password.</param>
        /// <returns>The result serialized to a <see cref="FormResult"/>.
        /// </returns>
        public async Task<FormResult> ResetPasswordAsync(string email, 
            string resetCode, string newPassword)
        {
            string[] defaultDetail = 
                [ "An unknown error prevented resetting the password." ];

            try
            {
                // make the request
                var result = await httpClient.PostAsJsonAsync(
                    "resetPassword", new
                    {
                        email,
                        resetCode,
                        newPassword
                    });

                // successful?
                if (result.IsSuccessStatusCode)
                {
                    return new FormResult { Succeeded = true };
                }

                // body should contain details about why it failed
                var details = await result.Content.ReadAsStringAsync();
                var problemDetails = JsonDocument.Parse(details);
                var errors = new List<string>();
                var errorList = problemDetails.RootElement.GetProperty("errors");

                foreach (var errorEntry in errorList.EnumerateObject())
                {
                    if (errorEntry.Value.ValueKind == JsonValueKind.String)
                    {
                        errors.Add(errorEntry.Value.GetString()!);
                    }
                    else if (errorEntry.Value.ValueKind == JsonValueKind.Array)
                    {
                        errors.AddRange(
                            errorEntry.Value.EnumerateArray().Select(
                                e => e.GetString() ?? string.Empty)
                            .Where(e => !string.IsNullOrEmpty(e)));
                    }
                }

                // return the error list
                return new FormResult
                {
                    Succeeded = false,
                    ErrorList = problemDetails == null ? defaultDetail : [.. errors]
                };
            }
            catch { }

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = defaultDetail
            };
        }

        /// <summary>
        /// Sends requests to the two-factor authentication endpoint for two-factor account management.
        /// </summary>
        /// <param name="twoFactorRequest">A set of optional parameters in <see cref="TwoFactorRequest"/> for 2FA management requests.</param>
        /// <returns>The result serialized to a <see cref="TwoFactorResponse"/>.</returns>
        public async Task<TwoFactorResponse> TwoFactorRequestAsync(TwoFactorRequest twoFactorRequest)
        {
            string[] defaultDetail = 
                [ "An unknown error prevented two-factor authentication." ];

            var response = await httpClient.PostAsJsonAsync("manage/2fa", twoFactorRequest, jsonSerializerOptions);

            // successful?
            if (response.IsSuccessStatusCode)
            {
                return await response.Content
                    .ReadFromJsonAsync<TwoFactorResponse>() ??
                    new()
                    { 
                        ErrorList = [ "There was an error processing the request." ]
                    };
            }

            // body should contain details about why it failed
            var details = await response.Content.ReadAsStringAsync();
            var problemDetails = JsonDocument.Parse(details);
            var errors = new List<string>();
            var errorList = problemDetails.RootElement.GetProperty("errors");

            foreach (var errorEntry in errorList.EnumerateObject())
            {
                if (errorEntry.Value.ValueKind == JsonValueKind.String)
                {
                    errors.Add(errorEntry.Value.GetString()!);
                }
                else if (errorEntry.Value.ValueKind == JsonValueKind.Array)
                {
                    errors.AddRange(
                        errorEntry.Value.EnumerateArray().Select(
                            e => e.GetString() ?? string.Empty)
                        .Where(e => !string.IsNullOrEmpty(e)));
                }
            }

            // return the error list
            return new TwoFactorResponse
            {
                ErrorList = problemDetails == null ? defaultDetail : [.. errors]
            };
        }

        /// <summary>
        /// User login with two-factor authentication.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="twoFactorCode">The user's password.</param>
        /// <returns>The result of the login request serialized to a <see cref="FormResult"/>.</returns>
        public async Task<FormResult> LoginTwoFactorRecoveryCodeAsync(string email, 
            string password, string twoFactorRecoveryCode)
        {
            try
            {
                // login with cookies
                var result = await httpClient.PostAsJsonAsync(
                    "login?useCookies=true", new
                    {
                        email,
                        password,
                        twoFactorRecoveryCode
                    });

                // success?
                if (result.IsSuccessStatusCode)
                {
                    // need to refresh auth state
                    NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());

                    // success!
                    return new FormResult { Succeeded = true };
                }
            }
            catch { }

            // unknown error
            return new FormResult
            {
                Succeeded = false,
                ErrorList = [ "Invalid recovery code." ]
            };
        }
    }
}
