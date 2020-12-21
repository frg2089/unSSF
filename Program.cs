using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using Ionic.Zlib;

namespace unSSF
{
    static class Program
    {
        static readonly byte[] aesKey = new byte[]{
                    0x52, 0x36, 0x46, 0x1A, 0xD3, 0x85, 0x03, 0x66,
                    0x90, 0x45, 0x16, 0x28, 0x79, 0x03, 0x36, 0x23,
                    0xDD, 0xBE, 0x6F, 0x03, 0xFF, 0x04, 0xE3, 0xCA,
                    0xD5, 0x7F, 0xFC, 0xA3, 0x50, 0xE4, 0x9E, 0xD9
                };

        static readonly byte[] iv = new byte[] {
                    0xE0, 0x7A, 0xAD, 0x35, 0xE0, 0x90, 0xAA, 0x03,
                    0x8A, 0x51, 0xFD, 0x05, 0xDF, 0x8C, 0x5D, 0x0F
                };

        static SymmetricAlgorithm SsfAES => new RijndaelManaged
        {
            Key = aesKey,
            IV = iv,
            Mode = CipherMode.CBC
        };

        /// <summary>
        /// 搜狗输入法皮肤包导出
        /// </summary>
        /// <param name="file">ssf文件</param>
        /// <param name="directory">导出目录</param>
        /// <returns></returns>
        // 我 不 听 建 议
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1835:对于 \"ReadAsync\" 和 \"WriteAsync\"，首选基于内存的重载", Justification = "<挂起>")]
        static async Task ExtractSsf(FileInfo file, DirectoryInfo directory)
        {
            if (!file.Exists)
                throw new FileNotFoundException(); // 找不到文件


            var buffer = new byte[1024]; // 准备一个buffer

            await using var fs = file.OpenRead(); // 打开文件

            await fs.ReadAsync(buffer, 0, 4); // 先读它四个字节
            switch (Encoding.ASCII.GetString(buffer, 0, 4))
            {
                case "Skin":// 是加密的包
                    {// using语句不能直接在switch语句中使用
                        await using var data = new MemoryStream();
                        {
                            fs.Seek(4, SeekOrigin.Current);// 跳过四个字节
                            await using var decrypted_ssfbin = new CryptoStream(fs, SsfAES.CreateDecryptor(), CryptoStreamMode.Read);// AES解码流
                            // 这个流不能Seek, 得想办法把它变成能Seek的流
                            await decrypted_ssfbin.ReadAsync(buffer, 0, 4);// 跳过四个字节, 这个流不能Seek 所以用读取4个字节的方式跳过
                            await using var tmps = new ZlibStream(decrypted_ssfbin, Ionic.Zlib.CompressionMode.Decompress);// 创建解压缩流解压缩文件
                            await tmps.CopyToAsync(data);// 把流中所有内容复制到可以Seek的流
                            data.Seek(0, SeekOrigin.Begin);// Seek! 设置指针在流开始的位置
                        }

                        await data.ReadAsync(buffer, 0, 8);// 读取8个字节(两个uint)

                        //var size = BitConverter.ToUInt32(buffer.ToArray(), 0);// 整体大小

                        uint[] offsets;
                        {
                            var offsets_length = BitConverter.ToInt32(buffer.ToArray(), 4);// 偏移信息长度
                            offsets = new uint[offsets_length / 4];// 初始化偏移信息数组(一个uint长4byte)
                            await data.ReadAsync(buffer, 0, offsets_length);// 将所有偏移信息一次读出来
                            for (int i = 0; i < offsets_length / 4; i++)// 计次循环
                                offsets[i] = BitConverter.ToUInt32(buffer.ToArray(), i * 4);// 一个一个转换
                        }

                        directory.Refresh();
                        if (!directory.Exists)// 检查目录是否存在
                            directory.Create();// 不存在就创建一个

                        foreach (var offset in offsets)// 遍历偏移数组
                        {
                            data.Seek(offset, SeekOrigin.Begin);// Seek到偏移位置

                            string filename;// 文件名
                            {
                                await data.ReadAsync(buffer, 0, 4);// 读取文件长度
                                var name_len = BitConverter.ToInt32(buffer.ToArray(), 0);

                                if (buffer.Length < name_len)// 防止buffer小了塞冒出来
                                    buffer = new byte[name_len];
                                await data.ReadAsync(buffer, 0, name_len);
                                filename = Encoding.Unicode.GetString(buffer.ToArray(), 0, name_len);// 文件名是Unicode编码的
                            }

                            await data.ReadAsync(buffer, 0, 4);// 读取内容长度
                            var content_len = BitConverter.ToInt32(buffer.ToArray(), 0);

                            if (buffer.Length < content_len)// 防止buffer小了塞冒出来
                                buffer = new byte[content_len];
                            await data.ReadAsync(buffer, 0, content_len);// 这里读取的就是内容了

                            await using var outfs = new FileInfo(Path.Combine(directory.FullName, filename)).OpenWrite();
                            await outfs.WriteAsync(buffer, 0, content_len);// 写入数据
                            await outfs.FlushAsync();// 流用完记得冲
                        }
                    }
                    break;
                case "\x50\x4b\x03\x04":// 这玩意是ZIP压缩包
                    ZipFile.ExtractToDirectory(file.FullName, directory.FullName);// 直接解压
                    break;
                default:// 是不认识的文件呢
                    throw new NotSupportedException();
            }
        }
        static async Task Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("unSSF <ssf file> [<out directory>]");
                return;
            }

            var source = new FileInfo(args[0]);

            var outdir = args.Length > 1
                ? new DirectoryInfo(args[1])
                : source.Directory.CreateSubdirectory(source.Name.Replace(source.Extension, string.Empty));

            await ExtractSsf(source, outdir);
        }
    }
}
