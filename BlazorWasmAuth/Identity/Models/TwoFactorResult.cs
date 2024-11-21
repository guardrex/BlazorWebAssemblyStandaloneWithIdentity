namespace BlazorWasmAuth.Identity.Models
{
    /// <summary>
    /// Response for login and registration.
    /// </summary>
    public class TwoFactorResult
    {
        /// <summary>
        /// Gets or sets a value indicating the shared key.
        /// </summary>
        public string SharedKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating the number of remaining recovery codes.
        /// </summary>
        public int RecoveryCodesLeft { get; set; } = 0;

        /// <summary>
        /// Gets or sets a value indicating the recovery codes.
        /// </summary>
        public string[] RecoveryCodes { get; set; } = [];

        /// <summary>
        /// Gets or sets a value indicating if two-factor authentication is enabled.
        /// </summary>
        public bool IsTwoFactorEnabled { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if the machine is remembered.
        /// </summary>
        public bool IsMachineRemembered { get; set; }

        /// <summary>
        /// On failure, the problem details are parsed and returned in this array.
        /// </summary>
        public string[] ErrorList { get; set; } = [];
    }
}
