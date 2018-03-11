using AspNetCore2AuthBoilerplate.Models;
using Dapper;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore2AuthBoilerplate.Services
{
    public interface IUsersService
    {
        /// <summary>
        /// Validates whether the username and password combination is valid
        /// </summary>
        /// <param name="email">User's email</param>
        /// <param name="password">User's password</param>
        /// <returns>True if valid, otherwise false</returns>
        Task<bool> ValidateCredentials(string email, string password);
        /// <summary>
        /// Finds a user by their email in a datastore
        /// </summary>
        /// <param name="email">User's e-mail address</param>
        /// <returns>User object</returns>
        Task<User> FindByEmail(string email);
        /// <summary>
        /// Validates clientId/secret combo against a datastore
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="secret"></param>
        /// <returns>True if valid, otherwise false</returns>
        Task<bool> ValidateClientIdAndSecretCombo(string clientId, string secret);
        /// <summary>
        /// Finds a user Id by the client Id that's passed in
        /// </summary>
        /// <param name="clientId">User's client Id</param>
        /// <returns>User's Id if found, else null</returns>
        Task<Guid?> GetUserIdentityByClientId(string clientId);
    }

    public class UsersService : IUsersService
    {
        private IConfiguration _configuration;
        private IDistributedCache _cache;

        public UsersService(IConfiguration configuration, IDistributedCache cache)
        {
            _configuration = configuration;
            _cache = cache;
        }

        public async Task<User> FindByEmail(string email)
        {
            string userString = await _cache.GetStringAsync($"user_{email}");
            if (!string.IsNullOrEmpty(userString))
            {
                return JsonConvert.DeserializeObject<User>(userString);
            }

            using (var db = new SqlConnection(_configuration.GetConnectionString("DefaultConnection")))
            {
                var userQuery = await db.QueryAsync<User>("SELECT Id, Email, Name, Bio FROM Users WHERE Email = @email", new { email });
                var user = userQuery.FirstOrDefault();
                var cacheOptions = new DistributedCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromHours(1));
                await _cache.SetStringAsync($"user_{user.Email}", JsonConvert.SerializeObject(user), cacheOptions);
                return user;
            }
        }

        public async Task<Guid?> GetUserIdentityByClientId(string clientId)
        {
            string userIdString = await _cache.GetStringAsync($"userId_{clientId}");
            if (!string.IsNullOrEmpty(userIdString))
            {
                return JsonConvert.DeserializeObject<Guid>(userIdString);
            }

            using (var db = new SqlConnection(_configuration.GetConnectionString("DefaultConnection")))
            {
                var accountIdQuery = await db.QueryAsync<Guid?>("SELECT UserId FROM ClientIds WHERE ClientId = @clientId", new { clientId });
                var userId = accountIdQuery.FirstOrDefault();
                var cacheOptions = new DistributedCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromHours(1));
                await _cache.SetStringAsync($"userId_{clientId}", userId.ToString(), cacheOptions);
                return userId;
            }
        }

        public async Task<bool> ValidateClientIdAndSecretCombo(string clientId, string secret)
        {
            string clientIdSecrets = await _cache.GetStringAsync($"ciscombo_{clientId}");
            if (!string.IsNullOrEmpty(clientIdSecrets))
            {
                var listOfSecrets = JsonConvert.DeserializeObject<List<string>>(clientIdSecrets);
                if (listOfSecrets.Contains(secret))
                {
                    return true;
                }
            }

            using (var db = new SqlConnection(_configuration.GetConnectionString("DefaultConnection")))
            {
                // Grab from database
                var cidQuery = await db.QueryAsync<string>("SELECT Secret FROM ClientIds WHERE ClientId = @clientId", new { clientId });
                var cidSecrets = cidQuery.ToList();

                if (!cidSecrets.Contains(secret))
                {
                    return false;
                }

                var cacheOptions = new DistributedCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromHours(1));
                await _cache.SetStringAsync($"ciscombo_{clientId}", JsonConvert.SerializeObject(cidSecrets), cacheOptions);
                return true;
            }
        }

        public async Task<bool> ValidateCredentials(string username, string password)
        {
            return true;
        }
    }
}
