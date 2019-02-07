using System.Collections.Generic;
using JwtEncryption.Models;
using JwtEncryption.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtEncryption.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IJwtService _jwtService;

        public UsersController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        // GET api/users/token?username=Admin&password=123
        [HttpGet("[action]")]
        public ActionResult<string> Token(string username, string password)
        {
            if (username != "Admin" || password != "123")
                return NotFound();

            var user = //find by UserName and Password from database
                new User { Id = 1, UserName = "Admin", FullName = "MJ Ebrahimi" };

            var token = _jwtService.Generate(user);

            return token;
        }

        // GET api/users
        [HttpGet]
        [Authorize] //need jwt token in header (Athorization: Bearer xyz) to authorize
        public ActionResult<IEnumerable<User>> Get()
        {
            return new User[]
            {
                new User { Id = 1, UserName = "Admin1", FullName = "MJ Ebrahimi (1)" },
                new User { Id = 2, UserName = "Admin2", FullName = "MJ Ebrahimi (2)" },
                new User { Id = 1, UserName = "Admin3", FullName = "MJ Ebrahimi (3)" }
            };
        }
    }
}
