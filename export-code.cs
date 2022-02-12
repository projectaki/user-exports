public class UserExportGenerator
    {
        public class UserExportModel
        {
            public string email { get; set; }
            public bool email_verified { get; set; }
            public string user_id { get; set; }
            //public AppMetadata app_metadata { get; set; }
            public CustomPasswordHash custom_password_hash { get; set; }
        }

        public class AppMetadata
        {
            public bool isExternal { get; set; }
        }

        public class CustomPasswordHash
        {
            public string algorithm { get; set; }
            public Hash hash { get; set; }
        }

        public class Hash
        {
            public string value { get; set; }
            public string encoding { get; set; }
        }
        private readonly Context _context;
        public UserExportGenerator(Context context)
        {
            _context = context;
        }

        public async Task<IEnumerable<UserExportModel>> GetUserExportObjects()
        {
            // User raw sql here because the password hash isnt on the Entity model.
            var users = await _context.Users
                        .FromSqlInterpolated($"select * from dbo.users where PasswordHash is not null")
                        .Where(x => !x.Deleted)
                        .ToListAsync();

            IEnumerable<UserExportModel> exportUsers = users.Select(TransformUserToExport);

            return exportUsers;

        }

        /// <summary>
        /// Lambda function which takes a user and returns an exported user.
        /// </summary>
        private Func<User, UserExportModel> TransformUserToExport = u => new UserExportModel
        {
            user_id = u.Id,
            email = u.Email,
            email_verified = true,
            custom_password_hash = new CustomPasswordHash
            {
                algorithm = "pbkdf2",
                hash = new Hash
                {
                    encoding = "utf8",
                    value = GenerateHash(u.PasswordHash)
                }

            },
            //app_metadata = new AppMetadata
            //{
            //    isExternal = u.IsExternal ?? false,
            //}

        };

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hash">The hash input is a base64 encoded string. Since it is made by Microsoft Identity Password Hasher v2,
        /// it is hashed with pbkdf2 algorithm using hmac-sha1, 256 bit key (32 bytes), and 128 bit (16 bytes) salt. The hash is composed
        /// of 49 bytes, and then base64 encoded. The first byte is a version number, therefore it has to be removed at the time of user export.
        /// Format of hash { 0th byte : version, 1-17 : salt, 18-49: key }
        /// Pseudocode >>
        /// - Decode the hash
        /// - Remove the first byte (version)
        /// - Get the salt
        /// - Get the key
        /// - Encode salt and key back with base64
        /// - Remove "=" character which is used for padding to fulfill auth0 requirements
        /// - Generate hash string for auth0 using provided format
        /// </param>
        /// <returns></returns>
        public static string GenerateHash(string hash)
        {
            // Decode
            byte[] data = Convert.FromBase64String(hash);

            byte[] saltBytes = data.Skip(1).Take(16).ToArray();
            byte[] keyBytes = data.Skip(17).Take(32).ToArray();
            
            string salt = Convert.ToBase64String(saltBytes);
            string key = Convert.ToBase64String(keyBytes);

            string saltWithoutPadding = new string(salt.ToCharArray().Where(c => c != "="[0]).ToArray());
            string keyWithoutPadding = new string(key.ToCharArray().Where(c => c != "="[0]).ToArray());

            var auth0String = $"$pbkdf2-sha1$i=1000,l=32${saltWithoutPadding}${keyWithoutPadding}";

            return auth0String;
        }
    }