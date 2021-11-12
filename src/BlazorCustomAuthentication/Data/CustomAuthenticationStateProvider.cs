using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Blazored.SessionStorage;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorCustomAuthentication.Data
{
    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
        private ISessionStorageService _sessionStorageService;

        public CustomAuthenticationStateProvider(ISessionStorageService sessionStorageService)
        {
            _sessionStorageService = sessionStorageService;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var email = await _sessionStorageService.GetItemAsStringAsync("email");
            ClaimsIdentity identity = email != null
                ? new ClaimsIdentity(new[] {new Claim(ClaimTypes.Name, email)}, "basic_user")
                : new ClaimsIdentity();
            var user = new ClaimsPrincipal(identity);
            return await Task.FromResult(new AuthenticationState(user));
        }

        public void MarkAsAuthenticated(string email)
        {
            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, email)
            }, "basic_user");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }

        public void MarkAsLoggedOut()
        {
            _sessionStorageService.RemoveItemAsync("email");
            NotifyAuthenticationStateChanged(   
                Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
        }
    }
}