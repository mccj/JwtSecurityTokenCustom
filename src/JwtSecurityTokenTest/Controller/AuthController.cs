using JwtSecurityTokenCustom.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtSecurityTokenTest
{
    /// <summary>
    /// 用户登入相关
    /// </summary>
    //[Controller]
    [ApiController]
    [Authorize]
    //[ControllerName("Auth")]
    //[Area("account")]
    //[Route("api/User/auth")]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        /// <summary>
        /// 根据账号密码获取授权信息
        /// </summary>
        /// <param name="password"></param>
        /// <param name="userName"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public virtual JwtTokenResult GetLoginJwtToken(string userName)
        {
            try
            {
                var user = new
                {
                    Id = "tid",
                    UserName = userName,
                    Avatar = "https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif",
                    Introduction = "测试",
                    Email = "test@qq.com",
                    PhoneNumber = "18888888888",
                    Roles = new[] { "TestRole" }
                };
                if (user != null)
                {
                    var token = this.HttpContext.IssueJwtToken(user.Id, user.UserName, user.Roles, user.Avatar, user.Introduction, user.Email, user.PhoneNumber);
                    return new JwtTokenResult { LoginResult = LoginResultType.Success, Token = "Bearer " + token };
                }
                return new JwtTokenResult { LoginResult = LoginResultType.InvalidUserNameOrPassword, Message = "用户不存在 或者 密码错误" };
            }
            catch (Exception ex)
            {
                throw new Exception("系统错误:" + ex.Message, ex);
            }
        }
        /// <summary>
        /// 获取当前登入账号的用户基本信息
        /// </summary>
        /// <param name="authorization"></param>
        /// <returns></returns>
        [HttpPost]
        [HttpGet]
        [Route("info")]
        public virtual ActionResult<UserInfoResult> GetInfo(/*[FromHeader(Name = "X-Token"), FromQuery(Name = "token")]string token*/[FromHeader(Name = "Authorization")] string authorization)
        {
            var claims = this.User.Claims;
            //var sid = claims.FirstOrDefault(f => f.Type == ClaimTypes.Sid)?.Value;
            //var nameIdentifier = claims.FirstOrDefault(f => f.Type == ClaimTypes.NameIdentifier)?.Value;
            var avatar = claims.FirstOrDefault(f => f.Type == "avatar")?.Value ?? "https://wpimg.wallstcn.com/f778738c-e4f8-4870-b634-56703b4acafe.gif";
            var name = claims.FirstOrDefault(f => f.Type == ClaimTypes.Name)?.Value;
            var givenName = claims.FirstOrDefault(f => f.Type == ClaimTypes.GivenName)?.Value;
            //var email = claims.FirstOrDefault(f => f.Type == ClaimTypes.Email)?.Value;
            //var mobilePhone = claims.FirstOrDefault(f => f.Type == ClaimTypes.MobilePhone)?.Value;

            var roles = claims.Where(f => f.Type == ClaimTypes.Role).Select(f => f.Value).ToArray();
            if (!roles.Any()) roles = new[] { "guest" };
            return new UserInfoResult() { Avatar = avatar, Introduction = givenName, Name = name, Roles = roles };
        }
        /// <summary>
        /// 退出当前登入
        /// </summary>
        /// <param name="authorization"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("logout")]
        public virtual bool Logout(/*[FromHeader(Name = "X-Token")]string token*/[FromHeader(Name = "Authorization")] string authorization)
        {
            return true;
        }
    }
}