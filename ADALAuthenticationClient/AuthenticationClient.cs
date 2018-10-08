using System;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace ADALAuthenticationClient
{
    public class AuthenticationClient
    {
        private readonly string clientId;

        private readonly string authenticationEndpoint;

        private readonly string[] scopes = { "user.read" };

        private readonly PublicClientApplication IdentityClientApp;
        private string UserToken = null;
        private DateTimeOffset Expiration;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationClient" /> class.
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="authenticationEndpoint"></param>
        /// <param name="scopes"></param>
        public AuthenticationClient(string clientId, string authenticationEndpoint, string[] scopes = null)
        {
            this.clientId = clientId;
            this.authenticationEndpoint = authenticationEndpoint;

            if (scopes != null)
            {
                this.scopes = scopes;
            }

            IdentityClientApp = new PublicClientApplication(clientId);
        }

        /// <summary>
        /// Retrives the Authentication for the User using Device Code Authentication
        /// </summary>
        /// <returns>Returns the Authentication Token as <see cref="string"/></returns>
        public async Task<string> GetTokenForUserUsingDeviceAuthAsync()
        {
            AuthenticationResult authResult;
            try
            {
                authResult = await IdentityClientApp.AcquireTokenSilentAsync(scopes, (IAccount)IdentityClientApp.GetAccountsAsync().Result);
                UserToken = authResult.AccessToken;
            }
            catch (Exception)
            {
                if (UserToken == null || Expiration <= DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    authResult = await IdentityClientApp.AcquireTokenWithDeviceCodeAsync(scopes, deviceCodeCallback =>
                    {
                        // This will print the message on the console which tells the user where to go sign-in using 
                        // a separate browser and the code to enter once they sign in.
                        // The AcquireTokenWithDeviceCodeAsync() method will poll the server after firing this
                        // device code callback to look for the successful login of the user via that browser.
                        // This background polling (whose interval and timeout data is also provided as fields in the 
                        // deviceCodeCallback class) will occur until:
                        // * The user has successfully logged in via browser and entered the proper code
                        // * The timeout specified by the server for the lifetime of this code (typically ~15 minutes) has been reached
                        // * The developing application calls the Cancel() method on a CancellationToken sent into the method.
                        //   If this occurs, an OperationCanceledException will be thrown (see catch below for more details).
                        Console.WriteLine(deviceCodeCallback.Message);
                        return Task.FromResult(0);
                    });

                    UserToken = authResult.AccessToken;
                    Expiration = authResult.ExpiresOn;
                }
            }

            return UserToken;
        }

        /// <summary>
        /// Retrives the Authentication for the User using a Authentication popup
        /// As fxcore does not support UI Components yet
        /// </summary>
        /// <returns>Returns the Authentication Token as <see cref="string"/></returns>
        public async Task<string> GetTokenForUserAsync()
        {
            AuthenticationResult authResult;
            try
            {
                authResult = await IdentityClientApp.AcquireTokenSilentAsync(scopes, (IAccount)IdentityClientApp.GetAccountsAsync().Result);
                UserToken = authResult.AccessToken;
            }
            catch (Exception)
            {
                if (UserToken == null || Expiration <= DateTimeOffset.UtcNow.AddMinutes(5))
                {
                    authResult = await IdentityClientApp.AcquireTokenAsync(scopes);

                    UserToken = authResult.AccessToken;
                    Expiration = authResult.ExpiresOn;
                }
            }

            return UserToken;
        }
    }
}
