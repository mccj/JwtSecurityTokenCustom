using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace Microsoft.AspNetCore.Authentication;

public static class AuthenticationJwtContextExtensions
{
    public static string IssueJwtToken(this HttpContext context, string userId, string userName, string[] roles, string avatar = null, string introduction = null, string email = null, string mobilePhone = null, string userData = null)
    {
        return IssueJwtToken(context, Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme, userId, userName, roles, avatar, introduction, email, mobilePhone, userData);
    }
    public static string IssueJwtToken(this HttpContext context, string scheme, string userId, string userName, string[] roles, string avatar = null, string introduction = null, string email = null, string mobilePhone = null, string userData = null)
    {
        var claims = new System.Collections.Generic.List<Claim>{
            new Claim(ClaimTypes.Sid,userId),
            new Claim(ClaimTypes.NameIdentifier,userName)
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        if (!string.IsNullOrWhiteSpace(avatar))
            claims.Add(new Claim("avatar", avatar));
        if (!string.IsNullOrWhiteSpace(introduction))
            claims.Add(new Claim(ClaimTypes.Name, introduction));
        if (!string.IsNullOrWhiteSpace(email))
            claims.Add(new Claim(ClaimTypes.Email, email));
        if (!string.IsNullOrWhiteSpace(mobilePhone))
            claims.Add(new Claim(ClaimTypes.MobilePhone, mobilePhone));

        if (!string.IsNullOrWhiteSpace(userData))
            claims.Add(new Claim(ClaimTypes.UserData, userData));

        return IssueJwtToken(context, scheme, claims);
    }
    public static string IssueJwtToken(this HttpContext context,/*int lifetime,*/ IEnumerable<Claim> claims)
    {
        return IssueJwtToken(context, Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme, claims);
    }
    public static string IssueJwtToken(this HttpContext context, string scheme, /*int lifetime,*/ IEnumerable<Claim> claims)
    {
        var _jwtSettings = context.RequestServices.GetService<IOptionsMonitor<JwtSecurity.JwtSettings>>().Get(scheme);
        //对称秘钥
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        //签名证书(秘钥，加密算法)
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        //生成token  [注意]需要nuget添加Microsoft.AspNetCore.Authentication.JwtBearer包，并引用System.IdentityModel.Tokens.Jwt命名空间
        var token = new JwtSecurityToken(_jwtSettings.Issuer, _jwtSettings.Audience, claims, DateTime.Now, DateTime.Now.AddDays(1), creds);

        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = jwtTokenHandler.WriteToken(token);//生成Token
        return jwtToken;
    }
    public static string IssueJwtToken(this HttpContext context/*int lifetime,*/ )
    {
        return IssueJwtToken(context, Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme, UserToClaims(context.User));
    }
    public static string IssueJwtToken(this HttpContext context, string scheme/*int lifetime,*/)
    {
        return IssueJwtToken(context, scheme, UserToClaims(context.User));
    }

    public static async Task<string> IssueJwtTokenAsync<TUser>(this SignInManager<TUser> signInManager, TUser user) where TUser : class
    {
        var userPrincipal = await signInManager.CreateUserPrincipalAsync(user);
        return AuthenticationJwtContextExtensions.IssueJwtToken(signInManager.Context, JwtBearer.JwtBearerDefaults.AuthenticationScheme, UserToClaims(userPrincipal));
    }
    public static async Task<string> IssueJwtTokenAsync<TUser>(this SignInManager<TUser> signInManager, string scheme, TUser user) where TUser : class
    {
        var userPrincipal = await signInManager.CreateUserPrincipalAsync(user);
        return AuthenticationJwtContextExtensions.IssueJwtToken(signInManager.Context, scheme, UserToClaims(userPrincipal));
    }
    public static async Task<string> IssueJwtTokenByPasswordAsync<TUser>(this SignInManager<TUser> signInManager, string scheme, string userName, string password) where TUser : class
    {
        if (string.IsNullOrWhiteSpace(userName)) throw new ArgumentNullException(nameof(userName));
        if (string.IsNullOrWhiteSpace(password)) throw new ArgumentNullException(nameof(password));

        var userManager = signInManager.Context.RequestServices.GetService<UserManager<TUser>>();
        var user = await userManager.FindByNameAsync(userName);
        if (user == null)
        {
            throw new Exception("用户不存在");
        }
        if (await userManager.CheckPasswordAsync(user, password))
        {
            return await AuthenticationJwtContextExtensions.IssueJwtTokenAsync(signInManager, scheme, user);
        }
        else
        {
            throw new Exception("密码错误");
        }
    }
    public static async Task<string> IssueJwtTokenByPasswordAsync<TUser>(this SignInManager<TUser> signInManager, string userName, string password) where TUser : class
    {
        return await AuthenticationJwtContextExtensions.IssueJwtTokenByPasswordAsync(signInManager, JwtBearer.JwtBearerDefaults.AuthenticationScheme, userName, password);
    }
    private static IEnumerable<Claim> UserToClaims(ClaimsPrincipal user)
    {
        //var claims = typeof(ClaimTypes).GetFields().ToDictionary(f => f.GetValue(null), f => f.Name);
        if (!user.Identity.IsAuthenticated) throw new Exception("当前用户未授权，无法生成授权码");
        return user.Claims;//.Select(f => new Claim(claims.ContainsKey(f.Type) ? claims[f.Type] : f.Type, f.Value));
    }

}
