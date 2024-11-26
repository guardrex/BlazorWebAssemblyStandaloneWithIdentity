namespace BlazorWasmAuth.Identity.Models;

public class LoginResponse
{
    public string? Type { get; set; }
    public string? Title { get; set; }
    public int Status { get; set; }
    public string? Detail { get; set; }
}
