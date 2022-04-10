namespace JwtSecurityTokenCustom.Models;

public class JwtTokenResult
{
    public string Token { get; set; }
    public string VerificationToken { get; set; }
    public LoginResultType LoginResult { get; set; }
    public string Message { get; set; }
}
