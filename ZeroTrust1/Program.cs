using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

public class EncryptedData
{
    [JsonPropertyName("salt")]
    public string Salt { get; set; }

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; }

    [JsonPropertyName("encryptedData")]
    public string EncryptedText { get; set; }

    [JsonPropertyName("tag")]
    public string Tag { get; set; }
}

class Program
{
    static void Main(string[] args)
    {
        string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string filePath = Path.Combine(appDataPath, "encryptedData.json");

        Console.WriteLine("1. Зашифровать данные");
        Console.WriteLine("2. Расшифровать данные");
        Console.Write("Выберите действие: ");
        string choice = Console.ReadLine();

        if (choice == "1")
        {
            Console.Write("Введите текст для шифрования: ");
            string plainText = Console.ReadLine();
            string password = GetPasswordFromUser();

            EncryptedData encryptedData = Encrypt(plainText, password);
            SaveToFile(encryptedData, filePath);

            Console.WriteLine("Данные успешно зашифрованы и сохранены.");
        }
        else if (choice == "2")
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("Файл с зашифрованными данными не найден.");
                return;
            }

            string password = GetPasswordFromUser();
            EncryptedData encryptedData = LoadFromFile(filePath);

            try
            {
                string decryptedText = Decrypt(encryptedData, password);
                Console.WriteLine($"Расшифрованный текст: {decryptedText}");
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Ошибка: неверный пароль или повреждённые данные.");
            }
        }
        else
        {
            Console.WriteLine("Неверный выбор.");
        }
    }

    public static byte[] GenerateKeyFromPassword(string password, byte[] salt, int keySize = 32)
    {
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        return deriveBytes.GetBytes(keySize);
    }

    public static EncryptedData Encrypt(string plainText, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        byte[] key = GenerateKeyFromPassword(password, salt);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] cipherText = new byte[plainBytes.Length];
        byte[] tag = new byte[16];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Encrypt(nonce, plainBytes, cipherText, tag);
        }

        Array.Clear(key, 0, key.Length);

        return new EncryptedData
        {
            Salt = Convert.ToBase64String(salt),
            Nonce = Convert.ToBase64String(nonce),
            EncryptedText = Convert.ToBase64String(cipherText),
            Tag = Convert.ToBase64String(tag)
        };
    }

    public static string Decrypt(EncryptedData encryptedData, string password)
    {
        byte[] salt = Convert.FromBase64String(encryptedData.Salt);
        byte[] nonce = Convert.FromBase64String(encryptedData.Nonce);
        byte[] cipherText = Convert.FromBase64String(encryptedData.EncryptedText);
        byte[] tag = Convert.FromBase64String(encryptedData.Tag);

        byte[] key = GenerateKeyFromPassword(password, salt);
        byte[] decryptedBytes = new byte[cipherText.Length];

        using (var aesGcm = new AesGcm(key))
        {
            aesGcm.Decrypt(nonce, cipherText, tag, decryptedBytes);
        }

        Array.Clear(key, 0, key.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }

    public static string GetPasswordFromUser()
    {
        Console.Write("Введите пароль: ");
        var securePassword = new SecureString();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) break;
            securePassword.AppendChar(key.KeyChar);
        }
        Console.WriteLine();

        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToBSTR(securePassword);
            return Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            if (ptr != IntPtr.Zero) Marshal.ZeroFreeBSTR(ptr);
        }
    }

    public static void SaveToFile(EncryptedData data, string filePath)
    {
        string json = JsonSerializer.Serialize(data);
        File.WriteAllText(filePath, json);
    }

    public static EncryptedData LoadFromFile(string filePath)
    {
        string json = File.ReadAllText(filePath);
        return JsonSerializer.Deserialize<EncryptedData>(json);
    }
}