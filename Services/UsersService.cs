using AspNetCore2AuthBoilerplate.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore2AuthBoilerplate.Services
{
    public interface IUsersService
    {
        Task<bool> ValidateCredentials(string email, string password);
        Task<User> FindByEmail(string email);
    }

    public class UsersService : IUsersService
    {
        public async Task<User> FindByEmail(string email)
        {
            throw new NotImplementedException();
        }

        public async Task<bool> ValidateCredentials(string username, string password)
        {
            throw new NotImplementedException();
        }
    }
}
