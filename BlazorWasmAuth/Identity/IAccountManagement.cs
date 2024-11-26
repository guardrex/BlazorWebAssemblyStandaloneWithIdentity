using BlazorWasmAuth.Identity.Models;

namespace BlazorWasmAuth.Identity
{
    /// <summary>
    /// Account management services.
    /// </summary>
    public interface IAccountManagement
    {
        /// <summary>
        /// Login service.
        /// </summary>
        /// <param name="email">User's email.</param>
        /// <param name="password">User's password.</param>
        /// <returns>The result of the request serialized to <see cref="FormResult"/>.</returns>
        public Task<FormResult> LoginAsync(string email, string password);

        /// <summary>
        /// Login service with two-factor authentication.
        /// </summary>
        /// <param name="email">User's email.</param>
        /// <param name="password">User's password.</param>
        /// <param name="twoFactorCode">User's 2FA code.</param>
        /// <returns>The result of the request serialized to <see cref="FormResult"/>.</returns>
        public Task<FormResult> LoginTwoFactorCodeAsync(
            string email, 
            string password, 
            string twoFactorCode);

        /// <summary>
        /// Log out the logged in user.
        /// </summary>
        /// <returns>The asynchronous task.</returns>
        public Task LogoutAsync();

        /// <summary>
        /// Registration service.
        /// </summary>
        /// <param name="email">User's email.</param>
        /// <param name="password">User's password.</param>
        /// <returns>The result of the request serialized to <see cref="FormResult"/>.</returns>
        public Task<FormResult> RegisterAsync(string email, string password);

        /// <summary>
        /// Authentication check.
        /// </summary>
        /// <returns>The result of the request serialized to <see cref="bool"/>.</returns>
        public Task<bool> CheckAuthenticatedAsync();

        /// <summary>
        /// Begin the password recovery process by issuing a POST request to the /forgotPassword endpoint.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <returns>A <see cref="bool"/> indicating success or failure.</returns>
        public Task<bool> ForgotPasswordAsync(string email);

        /// <summary>
        /// Reset the user's password.
        /// </summary>
        /// <param name="email">The user's email address.</param>
        /// <param name="resetCode">The user's reset code.</param>
        /// <param name="newPassword">The user's new password.</param>
        /// <returns>The result serialized to a <see cref="FormResult"/>.
        /// </returns>
        public Task<FormResult> ResetPasswordAsync(
            string email, 
            string resetCode, 
            string newPassword);

        /// <summary>
        /// Initial POST request to the two-factor authentication endpoint.
        /// </summary>
        /// <param name="enable">A flag indicating 2FA status.</param>
        /// <param name="twoFactorCode">The two-factor authentication code supplied by the user's 2FA app.</param>
        /// <param name="resetSharedKey">A flag indicating if the shared key should be reset.</param>
        /// <param name="resetRecoveryCodes">A flag indicating if the recovery codes should be reset.</param>
        /// <param name="forgetMachine">A flag indicating if the machine should be forgotten.</param>
        /// <returns>The result serialized to a <see cref="TwoFactorResult"/>.</returns>
        public Task<TwoFactorResult> TwoFactorRequestAsync(
            TwoFactorRequest twoFactorRequest);

        /// <summary>
        /// Login service with two-factor recovery authentication.
        /// </summary>
        /// <param name="email">User's email.</param>
        /// <param name="password">User's password.</param>
        /// <param name="twoFactorRecoveryCode">User's 2FA recovery code.</param>
        /// <returns>The result of the request serialized to <see cref="FormResult"/>.</returns>
        public Task<FormResult> LoginTwoFactorRecoveryCodeAsync(
            string email, 
            string password, 
            string twoFactorRecoveryCode);
    }
}
