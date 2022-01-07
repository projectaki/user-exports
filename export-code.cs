/// <summary>
/// Lambda function which takes a user and returns an exported user.
/// </summary>
private Func<User, UserExportModel> TransformUserToExport = u => new UserExportModel
{
    User_Id = u.Id,
    Email = u.Email,
    Email_Verified = true,
    Custom_Password_Hash = new CustomPasswordHash
    {
        Algorithm = "pbkdf2",
        Hash = new Hash
        {
            Encoding = "utf8",
            Value = GenerateHash(u.PasswordHash)
        }

    }

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
public static string GenerateHash(string hash) {
    // Decode
    byte[] data = Convert.FromBase64String(hash);

    byte[] saltBytes = data.Skip(1).Take(16).ToArray();
    byte[] keyBytes = data.Skip(17).Take(32).ToArray();

    string salt = Convert.ToBase64String(saltBytes);
    string key = Convert.ToBase64String(keyBytes);

    string saltWithoutPadding = string.Join("", salt.Split().Where(c => c != "="));
    string keyWithoutPadding = string.Join("", key.Split().Where(c => c != "="));

    var auth0String = $"$pbkdf2-sha1$i=1000,l=32${saltWithoutPadding}${keyWithoutPadding}";

    return auth0String;
}