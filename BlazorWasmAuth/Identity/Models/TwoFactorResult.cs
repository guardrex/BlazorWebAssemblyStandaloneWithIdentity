namespace BlazorWasmAuth.Identity.Models;

public class TwoFactorResult
{
    public string SharedKey { get; set; } = string.Empty;
    public int RecoveryCodesLeft { get; set; } = 0;
    public string[] RecoveryCodes { get; set; } = [];
    public bool IsTwoFactorEnabled { get; set; }
    public bool IsMachineRemembered { get; set; }
    public string[] ErrorList { get; set; } = [];
}
