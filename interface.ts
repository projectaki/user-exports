interface UserExport {
  email: string;
  email_verified: string;
  user_id: string;
  custom_password_hash: CustomPasswordHash;
}

interface CustomPasswordHash {
  algorithm: string;
  hash: Hash;
}

interface Hash {
  value: string;
  encoding: string;
}
