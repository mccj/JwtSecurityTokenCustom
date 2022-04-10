using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

public static class JwtBearerServiceCollectionExtensions
{
    public static IServiceCollection AddJwtBearer(this IServiceCollection services, string scheme = null, string issuer = null, string audience = null, string secretKey = null)
    {
        if (string.IsNullOrWhiteSpace(scheme)) scheme = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme;
        if (string.IsNullOrWhiteSpace(issuer)) issuer = "http://localhost";
        if (string.IsNullOrWhiteSpace(audience)) audience = "http://localhost";
        if (string.IsNullOrWhiteSpace(secretKey)) secretKey = "Hello-key----test";
        audience = audience + "/" + scheme;

        services.Configure<JwtSecurity.JwtSettings>(scheme, o => { o.Issuer = issuer; o.SecretKey = secretKey; o.Audience = audience; });

        //services.AddSingleton<IAuthorizationHandler, PermissionHandler>();
        //// 导入角色身份认证策略
        //services.AddAuthorization(options =>
        //{
        //    options.AddPolicy("Permission",
        //       policy => policy.Requirements.Add(roleRequirement));
        //});

        //身份认证类型
        services.AddAuthentication(scheme)
        //Jwt 认证配置
        .AddJwtBearer(scheme, options =>
        {
            //主要是jwt  token参数设置
            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                //Token颁发机构
                ValidIssuer = issuer,
                //颁发给谁
                ValidAudience =  audience,
                //这里的key要进行加密，需要引用Microsoft.IdentityModel.Tokens
                IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secretKey)),
                //ValidateIssuerSigningKey=true,
                ////是否验证Token有效期，使用当前时间与Token的Claims中的NotBefore和Expires对比
                //ValidateLifetime=true,
                ////允许的服务器时间偏移量
                //ClockSkew=TimeSpan.Zero
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
            };
            //options.Events = new JwtBearerEvents()
            //{
            //    // 在安全令牌通过验证和ClaimsIdentity通过验证之后调用
            //    // 如果用户访问注销页面
            //    OnTokenValidated = context =>
            //    {
            //        ////自定义授权
            //        //if (context.Request.Path.Value.ToString() == "/account/logout")
            //        //{
            //        var token = ((context as TokenValidatedContext).SecurityToken as JwtSecurityToken).RawData;
            //        //}
            //        return Task.CompletedTask;
            //    }
            //};

        });

        return services;
    }
}
