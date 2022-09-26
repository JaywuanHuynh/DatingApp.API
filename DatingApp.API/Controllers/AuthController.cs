using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Data.Entities;
using DatingApp.API.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace DatingApp.API.Controllers
{
  public class AuthController:BaseController
  {
    public readonly DataContext _context;
    public AuthController(DataContext context){
      _context=context;
    }

    [HttpGet("user")]
    public IEnumerable<User> Get(){
      var result= _context.AppUsers.ToList();
      if(result==null)
        throw new Exception("Users are null");
      return result;
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] AuthUserDto authUserDto){
      authUserDto.Username=authUserDto.Username.ToLower();
      if(_context.AppUsers.Any(u=>u.Username== authUserDto.Username))
      {
        return BadRequest("Username is already existed");
      }
      using var hmac =new HMACSHA512();
      var passwordbyte= Encoding.UTF8.GetBytes(authUserDto.Password);
      User user=new User{
        Username=authUserDto.Username,
        PasswordSalt=hmac.Key,
        PasswordHash=hmac.ComputeHash(passwordbyte)
      };
      _context.AppUsers.Add(user);
      _context.SaveChanges();
      return Ok(user.Username);
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] AuthUserDto authUserDto){
      var existingUser= _context.AppUsers.FirstOrDefault(e=>e.Username==authUserDto.Username);
      

      var hmac=new HMACSHA512(existingUser.PasswordSalt);
      var passwordbyte= Encoding.UTF8.GetBytes(authUserDto.Password);
      var tmp=hmac.ComputeHash(passwordbyte);


      if(tmp.SequenceEqual(existingUser.PasswordHash)){
        return Ok("accept");
      }
      else
        return BadRequest("deny");

    }
  }
}