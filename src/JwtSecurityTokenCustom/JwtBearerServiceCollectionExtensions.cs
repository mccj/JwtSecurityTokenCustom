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
        //// �����ɫ�����֤����
        //services.AddAuthorization(options =>
        //{
        //    options.AddPolicy("Permission",
        //       policy => policy.Requirements.Add(roleRequirement));
        //});

        //�����֤����
        services.AddAuthentication(scheme)
        //Jwt ��֤����
        .AddJwtBearer(scheme, options =>
        {
            //��Ҫ��jwt  token��������
            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                //Token�䷢����
                ValidIssuer = issuer,
                //�䷢��˭
                ValidAudience =  audience,
                //�����keyҪ���м��ܣ���Ҫ����Microsoft.IdentityModel.Tokens
                IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secretKey)),
                //ValidateIssuerSigningKey=true,
                ////�Ƿ���֤Token��Ч�ڣ�ʹ�õ�ǰʱ����Token��Claims�е�NotBefore��Expires�Ա�
                //ValidateLifetime=true,
                ////����ķ�����ʱ��ƫ����
                //ClockSkew=TimeSpan.Zero
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
            };
            //options.Events = new JwtBearerEvents()
            //{
            //    // �ڰ�ȫ����ͨ����֤��ClaimsIdentityͨ����֤֮�����
            //    // ����û�����ע��ҳ��
            //    OnTokenValidated = context =>
            //    {
            //        ////�Զ�����Ȩ
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
