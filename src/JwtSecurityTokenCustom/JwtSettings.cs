namespace JwtSecurity;

//public class TokenHandler
//{
//    private readonly IOptions<JwtSettings> _jwtSettingsAccesser;
//    public TokenHandler(IOptions<JwtSettings> jwtSettingsAccesser)
//    {
//        _jwtSettingsAccesser = jwtSettingsAccesser;
//    }

//    public string GetToken(string audience, string userId, string user, string[] roles, string avatar = null, string introduction = null, string email = null, string mobilePhone = null)
//    {
//        var _jwtSettings = _jwtSettingsAccesser.Value;
//        var claims = new System.Collections.Generic.List<Claim>{
//                new Claim(ClaimTypes.Sid,userId),
//                new Claim(ClaimTypes.NameIdentifier,user)
//            };
//        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

//        if (!string.IsNullOrWhiteSpace(avatar))
//            claims.Add(new Claim("avatar", avatar));
//        if (!string.IsNullOrWhiteSpace(introduction))
//            claims.Add(new Claim(ClaimTypes.Name, introduction));
//        if (!string.IsNullOrWhiteSpace(email))
//            claims.Add(new Claim(ClaimTypes.Email, email));
//        if (!string.IsNullOrWhiteSpace(mobilePhone))
//            claims.Add(new Claim(ClaimTypes.MobilePhone, mobilePhone));
//        //对称秘钥
//        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
//        //签名证书(秘钥，加密算法)
//        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//        //生成token  [注意]需要nuget添加Microsoft.AspNetCore.Authentication.JwtBearer包，并引用System.IdentityModel.Tokens.Jwt命名空间
//        var token = new JwtSecurityToken(_jwtSettings.Issuer, _jwtSettings.Audience + audience, claims, DateTime.Now, DateTime.Now.AddDays(1), creds);

//        var jwtTokenHandler = new JwtSecurityTokenHandler();
//        var jwtToken = jwtTokenHandler.WriteToken(token);//生成Token
//        return jwtToken;
//    }
//    public ClaimsPrincipal ValidateToken(string token)
//    {
//        var _jwtSettings = _jwtSettingsAccesser.Value;

//        // 密匙
//        string IssuerSigningKey = _jwtSettings.SecretKey;

//        // 发行
//        string ValidIssuer = _jwtSettings.Issuer;

//        // 观众
//        string ValidAudience = _jwtSettings.Audience;

//        var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(IssuerSigningKey));
//        var tokenValidationParams = new TokenValidationParameters()
//        {
//            ValidateLifetime = true,
//            ValidateAudience = true,
//            ValidateIssuer = true,
//            ValidateIssuerSigningKey = true,
//            ValidIssuer = ValidIssuer,
//            ValidAudience = ValidAudience,
//            IssuerSigningKey = secretKey,
//        };
//        var jwtTokenHandler = new JwtSecurityTokenHandler();
//        var claimsPrincipal = jwtTokenHandler.ValidateToken(token, tokenValidationParams, out SecurityToken _);
//        return claimsPrincipal;
//    }
//    //private void createToken(string user)
//    //{
//    //    var claim = new Claim[]{
//    //            new Claim(ClaimTypes.Name,user),
//    //            new Claim(ClaimTypes.Role,"admin")
//    //        };

//    //    //对称秘钥
//    //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
//    //    //签名证书(秘钥，加密算法)
//    //    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//    //    //_jwtSettings.Issuer, _jwtSettings.Audience, claim, DateTime.Now, DateTime.Now.AddDays(1), creds

//    //    var securityTokenDescriptor = new SecurityTokenDescriptor()
//    //    {
//    //        Subject = new ClaimsIdentity(claim), // Token的身份证，类似一个人可以有身份证，户口本
//    //        Expires = DateTime.Now.AddDays(1), // Token 有效期
//    //        SigningCredentials = creds,
//    //        // 生成一个Token证书，第一个参数是根据预先的二进制字节数组生成一个安全秘钥，说白了就是密码，第二个参数是编码方式  };
//    //    };
//    //    var tokenHandler = new JwtSecurityTokenHandler();
//    //    var securityToken = tokenHandler.CreateToken(securityTokenDescriptor);
//    //    var jwtSecurityToken = tokenHandler.CreateJwtSecurityToken(securityTokenDescriptor);
//    //    var claimsPrincipal = tokenHandler.CreateEncodedJwt(securityTokenDescriptor);

//    //    var securityTokenString = tokenHandler.WriteToken(securityToken);
//    //    var jwtSecurityTokenString = tokenHandler.WriteToken(jwtSecurityToken);
//    //}

//}

//public class PermissionHandler : IAuthorizationHandler
//{
//    public Task HandleAsync(AuthorizationHandlerContext context)
//    {
//        // 当前访问 Controller/Action 所需要的权限(策略授权)
//        IAuthorizationRequirement[] pendingRequirements = context.PendingRequirements.ToArray();

//        // 逐个检查
//        foreach (IAuthorizationRequirement requirement in pendingRequirements)
//        {
//            context.Succeed(requirement);
//        }


//        return Task.CompletedTask;
//    }
//}
///// <summary>
///// 验证用户信息，进行权限授权Handler
///// </summary>
//public class PermissionHandler3 : AuthorizationHandler<PermissionRequirement>
//{
//    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
//                                                   PermissionRequirement requirement)
//    {
//        List<PermissionRequirement> requirements = new List<PermissionRequirement>();
//        foreach (var item in context.Requirements)
//        {
//            requirements.Add((PermissionRequirement)item);
//        }
//        foreach (var item in requirements)
//        {
//            // 校验 颁发和接收对象
//            if (!(item.Issuer == AuthConfig.Issuer ?
//                item.Audience == AuthConfig.Audience ?
//                true : false : false))
//            {
//                context.Fail();
//            }
//            // 校验过期时间
//            var nowTime = DateTimeOffset.Now.ToUnixTimeSeconds();
//            var issued = item.IssuedTime + Convert.ToInt64(item.Expiration.TotalSeconds);
//            if (issued < nowTime)
//                context.Fail();



//            // 是否有访问此 API 的权限
//            var resource = ((Microsoft.AspNetCore.Routing.RouteEndpoint)context.Resource).RoutePattern;
//            var permissions = item.Roles.Permissions.ToList();
//            var apis = permissions.Any(x => x.Name.ToLower() == item.Roles.Name.ToLower() && x.Url.ToLower() == resource.RawText.ToLower());
//            if (!apis)
//                context.Fail();

//            context.Succeed(requirement);
//            // 无权限时跳转到某个页面
//            //var httpcontext = new HttpContextAccessor();
//            //httpcontext.HttpContext.Response.Redirect(item.DeniedAction);
//        }

//        context.Succeed(requirement);
//        return Task.CompletedTask;
//    }
//}
///// <summary>
///// 判断用户是否具有权限
///// </summary>
//public class PermissionHandler2 : IAuthorizationHandler
//{
//    public async Task HandleAsync(AuthorizationHandlerContext context)
//    {
//        // 当前访问 Controller/Action 所需要的权限(策略授权)
//        IAuthorizationRequirement[] pendingRequirements = context.PendingRequirements.ToArray();

//        // 取出用户信息
//        IEnumerable<Claim> claims = context.User?.Claims;

//        // 未登录或者取不到用户信息
//        if (claims is null)
//        {
//            context.Fail();
//            return;
//        }


//        // 取出用户名
//        Claim userName = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
//        if (userName is null)
//        {
//            context.Fail();
//            return;
//        }
//        // ... 省略一些检验过程 ...

//        // 获取此用户的信息
//        User user = UsersData.Users.FirstOrDefault(x => x.Name.Equals(userName.Value, StringComparison.OrdinalIgnoreCase));
//        List<Type> auths = user.Role.Requirements;

//        // 逐个检查
//        foreach (IAuthorizationRequirement requirement in pendingRequirements)
//        {
//            // 如果用户权限列表中没有找到此权限的话
//            if (!auths.Any(x => x == requirement.GetType()))
//                context.Fail();

//            context.Succeed(requirement);
//        }

//        await Task.CompletedTask;
//    }
//}
public class JwtSettings
{
    //声明的颁发者
    public string Issuer { get; set; }
    //token可以给哪些客户端使用
    public string Audience { get; set; }
    //加密的key
    public string SecretKey { get; set; }
}

