// 需将这段代码放入单独的控制台程序中运行

using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SimpleGameServer
{
    class Program
    {
        static RSACryptoServiceProvider _rsaProvider;
        static string _pubKeyXml;
        public static readonly ConcurrentDictionary<int, ClientSession> _sessions = new();
        static int _nextPlayerId = 0;

        static async Task Main(string[] args)
        {
            Console.WriteLine("服务器启动...");
            _rsaProvider = new RSACryptoServiceProvider(2048);
            _pubKeyXml = _rsaProvider.ToXmlString(false);
            Console.WriteLine("生成 RSA 公钥 (XML 格式)");

            var listener = new TcpListener(IPAddress.Any, 8080);
            listener.Start();
            Console.WriteLine("监听端口 8080");

            while (true)
            {
                var tcpClient = await listener.AcceptTcpClientAsync();
                Console.WriteLine("新连接: " + tcpClient.Client.RemoteEndPoint);
                var session = new ClientSession(tcpClient, _rsaProvider, _pubKeyXml, GeneratePlayerId);
                _ = session.RunAsync(() =>
                {
                    Console.WriteLine($"会话结束 (playerId={session.PlayerId})");
                    if (session.PlayerId > 0)
                    {
                        _sessions.TryRemove(session.PlayerId, out _);
                    }
                });
            }
        }

        static int GeneratePlayerId()
        {
            return System.Threading.Interlocked.Increment(ref _nextPlayerId);
        }
    }

    public class ClientSession
    {
        private const int MSG_LOGIN_REQUEST = 1;
        private const int MSG_LOGIN_RESPONSE = 2;
        private const int MSG_MOVE_REQUEST = 3;
        private const int MSG_MOVE_BROADCAST = 4;
        private const int MSG_PLAYER_JOIN = 5;
        private const int MSG_PLAYER_LEAVE = 6;
        private const int MSG_HEARTBEAT = 999;
        private const int MSG_REQ_SERVER_PUBKEY = 1000;
        private const int MSG_SERVER_PUBKEY = 1001;
        private const int MSG_CLIENT_AES_KEY = 1002;
        private const int MSG_SERVER_AES_ACK = 1003;

        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly RSACryptoServiceProvider _rsaProvider;
        private readonly string _pubKeyXml;
        private readonly Func<int> _generatePlayerId;

        private byte[] _aesKey = null;
        private bool _encryptionEnabled = false;

        public int PlayerId { get; private set; } = -1;

        public float X { get; private set; } = 0f;
        public float Y { get; private set; } = 0f;
        public float Z { get; private set; } = 0f;

        private byte[] _cache = new byte[0];
        private const int MaxPacketSize = 1024 * 1024;

        public ClientSession(TcpClient client, RSACryptoServiceProvider rsaProvider, string pubKeyXml, Func<int> genId)
        {
            _client = client;
            _stream = client.GetStream();
            _rsaProvider = rsaProvider;
            _pubKeyXml = pubKeyXml;
            _generatePlayerId = genId;
        }

        public async Task RunAsync(Action onClose = null)
        {
            try
            {
                var buffer = new byte[4096];
                while (true)
                {
                    int len = await _stream.ReadAsync(buffer, 0, buffer.Length);
                    if (len == 0) break;

                    AppendCache(buffer, len);
                    ProcessCache();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"异常: {ex.Message}");
            }
            finally
            {
                if (PlayerId > 0)
                {
                    Program._sessions.TryRemove(PlayerId, out _);

                    var leaveBroadcast = new PlayerLeaveBroadcast { playerId = PlayerId };
                    foreach (var kv in Program._sessions)
                    {
                        if (kv.Value.PlayerId > 0)
                        {
                            try
                            {
                                kv.Value.Send(MSG_PLAYER_LEAVE, leaveBroadcast);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"发送离开广播失败: {ex.Message}");
                            }
                        }
                    }
                    Console.WriteLine($"广播玩家离开: id={PlayerId}");
                }

                _client.Close();
                onClose?.Invoke();
            }
        }

        private void AppendCache(byte[] data, int len)
        {
            var newCache = new byte[_cache.Length + len];
            Array.Copy(_cache, 0, newCache, 0, _cache.Length);
            Array.Copy(data, 0, newCache, _cache.Length, len);
            _cache = newCache;
        }

        private void ProcessCache()
        {
            while (true)
            {
                if (_cache.Length < 4) return;

                var lenBytes = new byte[4];
                Array.Copy(_cache, 0, lenBytes, 0, 4);
                if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
                var bodyLen = BitConverter.ToInt32(lenBytes, 0);

                if (bodyLen <= 0 || bodyLen > MaxPacketSize)
                {
                    Console.WriteLine($"非法包长: {bodyLen}, 关闭连接");
                    _client.Close();
                    return;
                }

                if (_cache.Length < 4 + bodyLen) return;

                var body = new byte[bodyLen];
                Array.Copy(_cache, 4, body, 0, bodyLen);

                byte[] plainBody;
                if (_encryptionEnabled)
                {
                    try
                    {
                        plainBody = DecryptWithAes(body);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"AES 解密失败: {ex.Message}");
                        _client.Close();
                        return;
                    }
                }
                else
                {
                    plainBody = body;
                }

                HandleMessage(plainBody);

                var remain = new byte[_cache.Length - 4 - bodyLen];
                Array.Copy(_cache, 4 + bodyLen, remain, 0, remain.Length);
                _cache = remain;
            }
        }

        private void HandleMessage(byte[] plainBody)
        {
            var json = Encoding.UTF8.GetString(plainBody);
            var baseMsg = JsonConvert.DeserializeObject<BaseMsg>(json);
            int msgId = baseMsg.msgId;

            switch (msgId)
            {
                case MSG_REQ_SERVER_PUBKEY:
                    SendPlain(MSG_SERVER_PUBKEY, new { publicKey = _pubKeyXml });
                    Console.WriteLine("返回公钥给客户端");
                    break;

                case MSG_CLIENT_AES_KEY:
                    {
                        var net = JsonConvert.DeserializeObject<NetMessage<AesKeyRequest>>(json);
                        string b64 = net.data.encryptedKey;
                        var encryptedKey = Convert.FromBase64String(b64);

                        byte[] aesKey;
                        try
                        {
                            aesKey = _rsaProvider.Decrypt(encryptedKey, true);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("RSA 解密失败: " + ex.Message);
                            SendPlain(MSG_SERVER_AES_ACK, new { ok = false });
                            break;
                        }

                        _aesKey = aesKey;
                        _encryptionEnabled = true;
                        SendPlain(MSG_SERVER_AES_ACK, new { ok = true });
                        Console.WriteLine("AES 协商成功，后续启用 AES 加密");
                    }
                    break;

                case MSG_HEARTBEAT:
                    Send(MSG_HEARTBEAT, new { ping = "pong" });
                    break;

                case MSG_LOGIN_REQUEST:
                    {
                        var msg = JsonConvert.DeserializeObject<NetMessage<LoginRequest>>(json);
                        PlayerId = _generatePlayerId();

                        foreach (var kv in Program._sessions)
                        {
                            if (kv.Value.PlayerId > 0)
                            {
                                Send(MSG_PLAYER_JOIN, new { playerId = kv.Value.PlayerId });
                            }
                        }

                        Program._sessions[PlayerId] = this;

                        Console.WriteLine($"玩家登录: id={PlayerId}, name={msg.data.username ?? "unknown"}");
                        Send(MSG_LOGIN_RESPONSE, new { playerId = PlayerId, result = "ok" });

                        foreach (var kv in Program._sessions)
                        {
                            if (kv.Value.PlayerId > 0 && kv.Key != PlayerId)
                            {
                                var positionSync = new MoveBroadcast
                                {
                                    playerId = kv.Value.PlayerId,
                                    x = kv.Value.X,
                                    y = kv.Value.Y,
                                    z = kv.Value.Z
                                };
                                Send(MSG_MOVE_BROADCAST, positionSync);
                                Console.WriteLine($"同步玩家位置给新玩家: playerId={kv.Value.PlayerId}, pos=({kv.Value.X}, {kv.Value.Y}, {kv.Value.Z})");
                            }
                        }

                        var joinBroadcast = new PlayerJoinBroadcast { playerId = PlayerId };
                        foreach (var kv in Program._sessions)
                        {
                            if (kv.Key != PlayerId && kv.Value.PlayerId > 0)
                            {
                                kv.Value.Send(MSG_PLAYER_JOIN, joinBroadcast);
                            }
                        }
                        Console.WriteLine($"广播新玩家加入: id={PlayerId}");
                    }
                    break;

                case MSG_MOVE_REQUEST:
                    {
                        var mv = JsonConvert.DeserializeObject<NetMessage<MoveRequest>>(json);
                        var move = mv.data;

                        X = move.x;
                        Y = move.y;
                        Z = move.z;

                        var broadcast = new MoveBroadcast { playerId = move.playerId, x = move.x, y = move.y, z = move.z };

                        foreach (var kv in Program._sessions)
                        {
                            if (kv.Value.PlayerId > 0)
                            {
                                kv.Value.Send(MSG_MOVE_BROADCAST, broadcast);
                            }
                        }

                        Console.WriteLine($"玩家移动: id={move.playerId}, pos=({move.x}, {move.y}, {move.z})");
                    }
                    break;

                default:
                    Console.WriteLine($"未知消息ID: {msgId}");
                    break;
            }
        }

        private void SendPlain<T>(int msgId, T obj)
        {
            var body = BuildBody(msgId, obj);
            var lenBytes = BitConverter.GetBytes(body.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
            var packet = new byte[4 + body.Length];
            Array.Copy(lenBytes, 0, packet, 0, 4);
            Array.Copy(body, 0, packet, 4, body.Length);
            _stream.Write(packet, 0, packet.Length);
        }

        private void Send<T>(int msgId, T obj)
        {
            var body = BuildBody(msgId, obj);
            byte[] payload;
            if (_encryptionEnabled && _aesKey != null)
            {
                payload = EncryptWithAes(body);
            }
            else
            {
                payload = body;
            }

            var lenBytes = BitConverter.GetBytes(payload.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
            var packet = new byte[4 + payload.Length];
            Array.Copy(lenBytes, 0, packet, 0, 4);
            Array.Copy(payload, 0, packet, 4, payload.Length);
            try
            {
                _stream.Write(packet, 0, packet.Length);
            }
            catch { }
        }

        private byte[] BuildBody<T>(int msgId, T obj)
        {
            var wrapper = new NetMessage<T> { msgId = msgId, data = obj };
            var json = JsonConvert.SerializeObject(wrapper);
            return Encoding.UTF8.GetBytes(json);
        }

        private byte[] EncryptWithAes(byte[] plain)
        {
            using var aes = Aes.Create();
            aes.Key = _aesKey;
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var enc = aes.CreateEncryptor();
            var cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
            var result = new byte[aes.IV.Length + cipher.Length];
            Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
            Array.Copy(cipher, 0, result, aes.IV.Length, cipher.Length);
            return result;
        }

        private byte[] DecryptWithAes(byte[] ivAndCipher)
        {
            if (_aesKey == null) throw new Exception("AES Key empty");
            if (ivAndCipher.Length < 16) throw new Exception("payload too short");
            var iv = new byte[16];
            Array.Copy(ivAndCipher, 0, iv, 0, 16);
            var cipher = new byte[ivAndCipher.Length - 16];
            Array.Copy(ivAndCipher, 16, cipher, 0, cipher.Length);

            using var aes = Aes.Create();
            aes.Key = _aesKey;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var dec = aes.CreateDecryptor();
            var plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            return plain;
        }
    }

    public class BaseMsg { public int msgId; }
    public class NetMessage<T> { public int msgId; public T data; }
    public class LoginRequest { public string username; public string password; }
    public class MoveRequest { public int playerId; public float x; public float y; public float z; }
    public class MoveBroadcast { public int playerId; public float x; public float y; public float z; }
    public class PlayerJoinBroadcast { public int playerId; }
    public class PlayerLeaveBroadcast { public int playerId; }
    public class AesKeyRequest { public string encryptedKey; }
}
