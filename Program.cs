using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

if (!args.Any())
{
    await Console.Error.WriteLineAsync("unSSF <ssf file> [<out directory>]");
    return;
}

FileInfo sourceFile = new(args[0]);
if (!sourceFile.Exists)
    throw new FileNotFoundException();

DirectoryInfo targetFolder = args.Length > 1
    ? new(args[1])
    : sourceFile.Directory?.CreateSubdirectory(
        Path.GetFileNameWithoutExtension(sourceFile.Name)
        ?? throw new DirectoryNotFoundException()
    ) ?? throw new DirectoryNotFoundException();

// 检查目录是否存在
if (!targetFolder.Exists)
    // 不存在就创建一个
    targetFolder.Create();

byte[] buffer = new byte[1024];

Aes ssfAES = Aes.Create();
ssfAES.Key = new byte[]{
    0x52, 0x36, 0x46, 0x1A, 0xD3, 0x85, 0x03, 0x66,
    0x90, 0x45, 0x16, 0x28, 0x79, 0x03, 0x36, 0x23,
    0xDD, 0xBE, 0x6F, 0x03, 0xFF, 0x04, 0xE3, 0xCA,
    0xD5, 0x7F, 0xFC, 0xA3, 0x50, 0xE4, 0x9E, 0xD9
};
ssfAES.IV = new byte[]{
    0xE0, 0x7A, 0xAD, 0x35, 0xE0, 0x90, 0xAA, 0x03,
    0x8A, 0x51, 0xFD, 0x05, 0xDF, 0x8C, 0x5D, 0x0F
};
ssfAES.Mode = CipherMode.CBC;

await using FileStream fs = sourceFile.OpenRead();
await fs.ReadAsync(buffer.AsMemory(0, 4));

string flag = Encoding.ASCII.GetString(buffer.AsSpan(0, 4));
if (flag is "\x50\x4b\x03\x04")
{
    // 这玩意是ZIP压缩包
    // 所以直接解压
    ZipFile.ExtractToDirectory(sourceFile.FullName, targetFolder.FullName);
    return;
}

if (flag is not "Skin")
{
    // 是不认识的文件呢
    throw new NotSupportedException();
}

// 跳过四个字节 作用不明 或许是版本
fs.Seek(4, SeekOrigin.Current);

// AES解码流
await using CryptoStream decryptedSsf = new(
    fs,
    ssfAES.CreateDecryptor(),
    CryptoStreamMode.Read
);
// 跳过四个字节
if (decryptedSsf.CanSeek)
    decryptedSsf.Seek(4, SeekOrigin.Current);
else
    await decryptedSsf.ReadAsync(buffer.AsMemory(0, 4));

// 创建解压缩流解压缩文件
await using ZLibStream zLib = new(decryptedSsf, CompressionMode.Decompress);
// 这个流用不了Position
int pZLib = 0;

// 读取偏移信息长度
pZLib += await zLib.ReadAsync(buffer.AsMemory(0, 8));
int count = BitConverter.ToInt32(buffer, 4);
int size;
pZLib += count;

// 将所有偏移信息一次读出来
List<int> offsets = new(count);
while (count > 0)
{
    size = await zLib.ReadAsync(
        buffer.AsMemory(0, Math.Min(buffer.Length, count))
    );
    count -= size;
    offsets.AddRange(
        Enumerable
            .Range(0, size / 4)
            .Select(i => BitConverter.ToInt32(buffer, i * 4))
    );
}

StringBuilder stringBuilder = new();
// 遍历偏移数组
foreach (int item in offsets)
{
    // Seek到偏移位置
    count = item - pZLib;
    pZLib += count;
    while (count > 0)
    {
        size = await zLib.ReadAsync(
            buffer.AsMemory(0, Math.Min(buffer.Length, count))
        );
        count -= size;
    }

    // 读取文件长度
    pZLib += await zLib.ReadAsync(buffer.AsMemory(0, 4));
    count = BitConverter.ToInt32(buffer.ToArray(), 0);
    pZLib += count;

    // 文件名
    stringBuilder.Clear();
    while (count > 0)
    {
        size = await zLib.ReadAsync(
            buffer.AsMemory(0, Math.Min(buffer.Length, count))
        );
        count -= size;
        // 记录文件名
        stringBuilder.Append(Encoding.Unicode.GetString(buffer, 0, size));
    }

    // 读取内容长度
    pZLib += await zLib.ReadAsync(buffer.AsMemory(0, 4));
    count = BitConverter.ToInt32(buffer, 0);
    pZLib += count;

    // 这里读取的就是内容了
    await using FileStream target = File.Create(
        Path.Combine(targetFolder.FullName, stringBuilder.ToString())
    );
    while (count > 0)
    {
        size = await zLib.ReadAsync(
            buffer.AsMemory(0, Math.Min(buffer.Length, count))
        );
        count -= size;
        // 写入数据到文件
        await target.WriteAsync(buffer.AsMemory(0, size));
    }
    // 流用完记得冲
    await target.FlushAsync();
}
