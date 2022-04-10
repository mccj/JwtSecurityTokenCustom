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
//        //�Գ���Կ
//        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
//        //ǩ��֤��(��Կ�������㷨)
//        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//        //����token  [ע��]��Ҫnuget���Microsoft.AspNetCore.Authentication.JwtBearer����������System.IdentityModel.Tokens.Jwt�����ռ�
//        var token = new JwtSecurityToken(_jwtSettings.Issuer, _jwtSettings.Audience + audience, claims, DateTime.Now, DateTime.Now.AddDays(1), creds);

//        var jwtTokenHandler = new JwtSecurityTokenHandler();
//        var jwtToken = jwtTokenHandler.WriteToken(token);//����Token
//        return jwtToken;
//    }
//    public ClaimsPrincipal ValidateToken(string token)
//    {
//        var _jwtSettings = _jwtSettingsAccesser.Value;

//        // �ܳ�
//        string IssuerSigningKey = _jwtSettings.SecretKey;

//        // ����
//        string ValidIssuer = _jwtSettings.Issuer;

//        // ����
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

//    //    //�Գ���Կ
//    //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
//    //    //ǩ��֤��(��Կ�������㷨)
//    //    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//    //    //_jwtSettings.Issuer, _jwtSettings.Audience, claim, DateTime.Now, DateTime.Now.AddDays(1), creds

//    //    var securityTokenDescriptor = new SecurityTokenDescriptor()
//    //    {
//    //        Subject = new ClaimsIdentity(claim), // Token�����֤������һ���˿��������֤�����ڱ�
//    //        Expires = DateTime.Now.AddDays(1), // Token ��Ч��
//    //        SigningCredentials = creds,
//    //        // ����һ��Token֤�飬��һ�������Ǹ���Ԥ�ȵĶ������ֽ���������һ����ȫ��Կ��˵���˾������룬�ڶ��������Ǳ��뷽ʽ  };
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
//        // ��ǰ���� Controller/Action ����Ҫ��Ȩ��(������Ȩ)
//        IAuthorizationRequirement[] pendingRequirements = context.PendingRequirements.ToArray();

//        // ������
//        foreach (IAuthorizationRequirement requirement in pendingRequirements)
//        {
//            context.Succeed(requirement);
//        }


//        return Task.CompletedTask;
//    }
//}
///// <summary>
///// ��֤�û���Ϣ������Ȩ����ȨHandler
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
//            // У�� �䷢�ͽ��ն���
//            if (!(item.Issuer == AuthConfig.Issuer ?
//                item.Audience == AuthConfig.Audience ?
//                true : false : false))
//            {
//                context.Fail();
//            }
//            // У�����ʱ��
//            var nowTime = DateTimeOffset.Now.ToUnixTimeSeconds();
//            var issued = item.IssuedTime + Convert.ToInt64(item.Expiration.TotalSeconds);
//            if (issued < nowTime)
//                context.Fail();



//            // �Ƿ��з��ʴ� API ��Ȩ��
//            var resource = ((Microsoft.AspNetCore.Routing.RouteEndpoint)context.Resource).RoutePattern;
//            var permissions = item.Roles.Permissions.ToList();
//            var apis = permissions.Any(x => x.Name.ToLower() == item.Roles.Name.ToLower() && x.Url.ToLower() == resource.RawText.ToLower());
//            if (!apis)
//                context.Fail();

//            context.Succeed(requirement);
//            // ��Ȩ��ʱ��ת��ĳ��ҳ��
//            //var httpcontext = new HttpContextAccessor();
//            //httpcontext.HttpContext.Response.Redirect(item.DeniedAction);
//        }

//        context.Succeed(requirement);
//        return Task.CompletedTask;
//    }
//}
///// <summary>
///// �ж��û��Ƿ����Ȩ��
///// </summary>
//public class PermissionHandler2 : IAuthorizationHandler
//{
//    public async Task HandleAsync(AuthorizationHandlerContext context)
//    {
//        // ��ǰ���� Controller/Action ����Ҫ��Ȩ��(������Ȩ)
//        IAuthorizationRequirement[] pendingRequirements = context.PendingRequirements.ToArray();

//        // ȡ���û���Ϣ
//        IEnumerable<Claim> claims = context.User?.Claims;

//        // δ��¼����ȡ�����û���Ϣ
//        if (claims is null)
//        {
//            context.Fail();
//            return;
//        }


//        // ȡ���û���
//        Claim userName = claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
//        if (userName is null)
//        {
//            context.Fail();
//            return;
//        }
//        // ... ʡ��һЩ������� ...

//        // ��ȡ���û�����Ϣ
//        User user = UsersData.Users.FirstOrDefault(x => x.Name.Equals(userName.Value, StringComparison.OrdinalIgnoreCase));
//        List<Type> auths = user.Role.Requirements;

//        // ������
//        foreach (IAuthorizationRequirement requirement in pendingRequirements)
//        {
//            // ����û�Ȩ���б���û���ҵ���Ȩ�޵Ļ�
//            if (!auths.Any(x => x == requirement.GetType()))
//                context.Fail();

//            context.Succeed(requirement);
//        }

//        await Task.CompletedTask;
//    }
//}
public class JwtSettings
{
    //�����İ䷢��
    public string Issuer { get; set; }
    //token���Ը���Щ�ͻ���ʹ��
    public string Audience { get; set; }
    //���ܵ�key
    public string SecretKey { get; set; }
}

