using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using UnityEngine;

public class NetworkManager : MonoBehaviour
{
    [SerializeField] private Material localPlayerMaterial;
    [SerializeField] private Material remotePlayerMaterial;

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

    private TcpClient _client;
    private NetworkStream _stream;
    private CancellationTokenSource _cts;

    private byte[] _cache = new byte[0];

    private const float HeartbeatInterval = 5f;
    private const float HeartbeatTimeout = HeartbeatInterval * 3;
    private float _lastHeartbeat;
    private float _lastPongTime;
    private const int MaxPacketSize = 1024 * 1024;

    private bool _reconnecting = false;

    private bool _encryptionEnabled = false;
    private byte[] _aesKey = null;
    private TaskCompletionSource<string> _pubKeyTcs;
    private TaskCompletionSource<bool> _aesAckTcs;

    private int _reconnectAttempts = 0;
    private const int MaxReconnectAttempts = 5;

    private readonly object _closeLock = new();
    private bool _isClosing = false;
    private bool _isApplicationQuitting = false;

    private UdpClient _udpClient;
    private IPEndPoint _serverUdpEndPoint;
    private const int UdpPort = 9000;

    [SerializeField] private string serverIp = "127.0.0.1";
    [SerializeField] private int serverTcpPort = 8080;

    [SerializeField] private float remoteLerpSpeed = 12f;   // 越大越快跟上

    void Start()
    {
        _serverUdpEndPoint = new IPEndPoint(IPAddress.Parse(serverIp), UdpPort);
        _udpClient = new UdpClient();
        _ = ReceiveUdpLoopAsync();

        _ = ConnectAsync(serverIp, serverTcpPort);
    }

    public async Task ConnectAsync(string host, int port)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();

        try
        {
            _client = new();
            await _client.ConnectAsync(IPAddress.Parse(host), port);
            _stream = _client.GetStream();

            Debug.Log("连接服务器成功");
            _ = ReceiveLoopAsync(_cts.Token);

            await PerformKeyExchangeAsync();

            _lastPongTime = Time.time;
            _reconnectAttempts = 0;
        }
        catch (Exception ex)
        {
            Debug.LogError($"连接失败: {ex.Message}");
            await TryReconnectAsync(host, port);
        }
    }

    public async Task SendMsgAsync<T>(int msgId, T obj)
    {
        if (_client == null || !_client.Connected || _isApplicationQuitting) return;

        try
        {
            if (_encryptionEnabled)
            {
                var body = MsgUtil.BuildMessageBody(msgId, obj);
                var encrypted = EncryptWithAes(body);

                var lenBytes = BitConverter.GetBytes(encrypted.Length);
                if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
                var packet = new byte[4 + encrypted.Length];
                Array.Copy(lenBytes, 0, packet, 0, 4);
                Array.Copy(encrypted, 0, packet, 4, encrypted.Length);
                await _stream.WriteAsync(packet, 0, packet.Length, _cts.Token);
            }
            else
            {
                var packet = MsgUtil.EncodeMessage(msgId, obj);
                await _stream.WriteAsync(packet, 0, packet.Length, _cts.Token);
            }
        }
        catch (Exception e)
        {
            if (!_isApplicationQuitting)
            {
                Debug.LogError($"发送异常: {e.Message}");
                _ = TryReconnectAsync(serverIp, serverTcpPort);
            }
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken token)
    {
        var buffer = new byte[4096];

        try
        {
            while (!token.IsCancellationRequested && !_isApplicationQuitting)
            {
                int len = await _stream.ReadAsync(buffer, 0, buffer.Length, token);
                if (len == 0) throw new Exception("服务器断开连接");

                AppendCache(buffer, len);
                ProcessCache();
            }
        }
        catch (OperationCanceledException)
        {
            Debug.Log("接收循环被取消");
        }
        catch (Exception e)
        {
            if (!_isApplicationQuitting)
            {
                Debug.LogWarning($"接收异常: {e.Message}");
                _ = TryReconnectAsync(serverIp, serverTcpPort);
            }
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
                Debug.LogError($"非法包长度: {bodyLen}, 强制断开连接");
                CloseConnection();
                return;
            }

            if (_cache.Length < 4 + bodyLen) return;

            var body = new byte[bodyLen];
            Array.Copy(_cache, 4, body, 0, bodyLen);

            byte[] plainBody;
            try
            {
                plainBody = _encryptionEnabled ? DecryptWithAes(body) : body;
            }
            catch (Exception ex)
            {
                Debug.LogError($"解密失败: {ex.Message}，断开连接");
                CloseConnection();
                return;
            }

            HandleMessage(plainBody);

            var remain = new byte[_cache.Length - 4 - bodyLen];
            Array.Copy(_cache, 4 + bodyLen, remain, 0, remain.Length);
            _cache = remain;
        }
    }

    private void HandleMessage(byte[] plainBody)
    {
        var msgId = MsgUtil.GetMessageId(plainBody);

        switch (msgId)
        {
            case MSG_SERVER_PUBKEY:
                var pub = MsgUtil.DecodeMessage<ServerPubKeyMsg>(plainBody);
                _pubKeyTcs?.TrySetResult(pub.data.publicKey);
                break;

            case MSG_SERVER_AES_ACK:
                _aesAckTcs?.TrySetResult(true);
                _encryptionEnabled = true;
                break;

            case MSG_LOGIN_RESPONSE:
                var loginResp = MsgUtil.DecodeMessage<LoginResponse>(plainBody);
                Debug.Log($"登录成功! 玩家ID={loginResp.data.playerId}");
                _myPlayerId = loginResp.data.playerId;
                SpawnPlayer(_myPlayerId, true);
                _ = SendUdpMoveAsync(_myPlayerId, _players[_myPlayerId].transform.position);
                break;

            case MSG_MOVE_BROADCAST:
                var mv = MsgUtil.DecodeMessage<MoveBroadcast>(plainBody);
                UpdateOrSpawnRemotePlayer(mv.data.playerId, mv.data.x, mv.data.y, mv.data.z, true);
                break;

            case MSG_PLAYER_JOIN:
                var joinMsg = MsgUtil.DecodeMessage<PlayerJoinBroadcast>(plainBody);
                if (joinMsg.data.playerId != _myPlayerId && !_players.ContainsKey(joinMsg.data.playerId))
                {
                    SpawnPlayer(joinMsg.data.playerId, false);
                }
                break;

            case MSG_PLAYER_LEAVE:
                var leaveMsg = MsgUtil.DecodeMessage<PlayerLeaveBroadcast>(plainBody);
                if (_players.ContainsKey(leaveMsg.data.playerId))
                {
                    Destroy(_players[leaveMsg.data.playerId]);
                    _players.Remove(leaveMsg.data.playerId);
                    _remoteStates.Remove(leaveMsg.data.playerId);
                }
                break;

            case MSG_HEARTBEAT:
                _lastPongTime = Time.time;
                break;

            default:
                Debug.Log($"收到未知消息 ID={msgId}");
                break;
        }
    }

    private int _myPlayerId = -1;

    private readonly Dictionary<int, GameObject> _players = new();

    private class RemoteState
    {
        public Vector3 Target;
    }
    private readonly Dictionary<int, RemoteState> _remoteStates = new();

    private void SpawnPlayer(int playerId, bool isLocal)
    {
        if (_players.ContainsKey(playerId)) return;
        var go = GameObject.CreatePrimitive(PrimitiveType.Capsule);
        go.name = "Player_" + playerId;
        go.transform.position = Vector3.zero;

        var renderer = go.GetComponent<Renderer>();

        if (isLocal)
        {
            if (localPlayerMaterial != null) renderer.material = localPlayerMaterial;
            else { var m = new Material(Shader.Find("Standard")); m.color = Color.green; renderer.material = m; }
            go.AddComponent<LocalPlayerController>().Init(this, playerId);
        }
        else
        {
            if (remotePlayerMaterial != null) renderer.material = remotePlayerMaterial;
            else { var m = new Material(Shader.Find("Standard")); m.color = Color.red; renderer.material = m; }

            _remoteStates[playerId] = new RemoteState { Target = Vector3.zero };
        }
        _players[playerId] = go;

        if (isLocal)
        {
            Camera.main.transform.position = go.transform.position + new Vector3(0, 5, -6);
            Camera.main.transform.LookAt(go.transform);
        }
    }

    private void UpdateOrSpawnRemotePlayer(int playerId, float x, float y, float z, bool snap = false)
    {
        if (!_players.ContainsKey(playerId))
        {
            SpawnPlayer(playerId, playerId == _myPlayerId);
        }

        var go = _players[playerId];
        if (playerId == _myPlayerId)
        {
            if (snap) go.transform.position = new Vector3(x, y, z);
            return;
        }

        if (!_remoteStates.ContainsKey(playerId))
            _remoteStates[playerId] = new RemoteState();

        _remoteStates[playerId].Target = new Vector3(x, y, z);

        if (snap) go.transform.position = _remoteStates[playerId].Target;
    }

    public async Task SendUdpMoveAsync(int playerId, Vector3 pos)
    {
        try
        {
            var mv = new MoveBroadcast { playerId = playerId, x = pos.x, y = pos.y, z = pos.z };
            var json = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(mv));
            await _udpClient.SendAsync(json, json.Length, _serverUdpEndPoint);
        }
        catch (Exception e)
        {
            Debug.LogWarning($"UDP 发送失败: {e.Message}");
        }
    }

    private async Task ReceiveUdpLoopAsync()
    {
        while (!_isApplicationQuitting)
        {
            try
            {
                var result = await _udpClient.ReceiveAsync();
                var mv = JsonConvert.DeserializeObject<MoveBroadcast>(Encoding.UTF8.GetString(result.Buffer));
                if (mv == null) continue;
                if (mv.playerId == _myPlayerId) continue;

                UpdateOrSpawnRemotePlayer(mv.playerId, mv.x, mv.y, mv.z);
            }
            catch {}
        }
    }

    private async Task PerformKeyExchangeAsync()
    {
        _pubKeyTcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        await SendPlainMsgAsync(MSG_REQ_SERVER_PUBKEY, new { request = "give_pubkey" });

        string serverPubKeyXml = await _pubKeyTcs.Task;

        _aesKey = new byte[32];
        RandomNumberGenerator.Fill(_aesKey);

        var rsaProv = new RSACryptoServiceProvider();
        rsaProv.FromXmlString(serverPubKeyXml);
        var encryptedAesKey = rsaProv.Encrypt(_aesKey, true);
        rsaProv.Dispose();

        var b64 = Convert.ToBase64String(encryptedAesKey);
        _aesAckTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        await SendPlainMsgAsync(MSG_CLIENT_AES_KEY, new { encryptedKey = b64 });

        var ok = await _aesAckTcs.Task;
        if (ok)
        {
            Debug.Log("AES 协商成功");
            _encryptionEnabled = true;
            _lastPongTime = Time.time;

            await SendMsgAsync(MSG_LOGIN_REQUEST, new { username = $"player_{Guid.NewGuid().ToString("N")[..8]}", password = "123456" });
        }
    }

    private async Task SendPlainMsgAsync<T>(int msgId, T obj)
    {
        var packet = MsgUtil.EncodeMessage(msgId, obj);
        await _stream.WriteAsync(packet, 0, packet.Length, _cts.Token);
    }

    private byte[] EncryptWithAes(byte[] plain)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _aesKey;
        aes.GenerateIV();
        using var encryptor = aes.CreateEncryptor();
        var cipher = encryptor.TransformFinalBlock(plain, 0, plain.Length);
        var result = new byte[aes.IV.Length + cipher.Length];
        Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
        Array.Copy(cipher, 0, result, aes.IV.Length, cipher.Length);
        return result;
    }

    private byte[] DecryptWithAes(byte[] ivAndCipher)
    {
        var iv = new byte[16];
        Array.Copy(ivAndCipher, 0, iv, 0, 16);
        var cipher = new byte[ivAndCipher.Length - 16];
        Array.Copy(ivAndCipher, 16, cipher, 0, cipher.Length);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _aesKey;
        aes.IV = iv;
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
    }

    private async Task TryReconnectAsync(string host, int port)
    {
        if (_reconnecting || _isApplicationQuitting) return;

        lock (_closeLock) { if (_isClosing || _isApplicationQuitting) return; }
        _reconnecting = true;

        try
        {
            if (_reconnectAttempts >= MaxReconnectAttempts)
            {
                Debug.LogError("达到最大重连次数，停止重连");
                return;
            }

            _reconnectAttempts++;
            Debug.LogWarning($"尝试重连中... (第{_reconnectAttempts}次)");
            CloseConnection();

            for (int i = 0; i < 30; i++) { if (_isApplicationQuitting) return; await Task.Delay(100); }
            if (!_isApplicationQuitting) { await ConnectAsync(host, port); }
        }
        catch (Exception ex)
        {
            if (!_isApplicationQuitting) Debug.LogError($"重连过程中发生异常: {ex.Message}");
        }
        finally { _reconnecting = false; }
    }

    private void CloseConnection()
    {
        lock (_closeLock) { if (_isClosing) return; _isClosing = true; }

        try
        {
            Debug.Log("正在关闭网络连接...");

            try { _cts?.Cancel(); } catch (Exception ex) { Debug.LogWarning($"取消异步操作时出错: {ex.Message}"); }
            try
            {
                _pubKeyTcs?.TrySetCanceled();
                _aesAckTcs?.TrySetCanceled();
                _pubKeyTcs = null; _aesAckTcs = null;
            }
            catch (Exception ex) { Debug.LogWarning($"重置TaskCompletionSource时出错: {ex.Message}"); }

            try { _stream?.Close(); _stream?.Dispose(); _stream = null; } catch (Exception ex) { Debug.LogWarning($"关闭网络流时出错: {ex.Message}"); }

            try
            {
                if (_client != null)
                {
                    if (_client.Connected) _client.GetStream()?.Close();
                    _client.Close(); _client = null;
                }
            }
            catch (Exception ex) { Debug.LogWarning($"关闭TCP客户端时出错: {ex.Message}"); }

            _encryptionEnabled = false; _aesKey = null; _cache = new byte[0];
            _myPlayerId = -1; _lastHeartbeat = 0; _lastPongTime = 0;

            if (!_isApplicationQuitting) ClearAllPlayers();

            Debug.Log("网络连接已关闭");
        }
        catch (Exception ex) { Debug.LogError($"关闭连接时发生异常: {ex.Message}"); }
        finally { lock (_closeLock) { _isClosing = false; } }
    }

    private void ClearAllPlayers()
    {
        try
        {
            foreach (var kv in _players)
            {
                if (kv.Value != null) Destroy(kv.Value);
            }
            _players.Clear();
            _remoteStates.Clear();
            Debug.Log("已清理所有玩家对象");
        }
        catch (Exception ex)
        {
            Debug.LogError($"清理玩家对象时出错: {ex.Message}");
        }
    }

    void Update()
    {
        if (_isApplicationQuitting) return;

        if (_client != null && _client.Connected)
        {
            if (Time.time - _lastHeartbeat > HeartbeatInterval)
            {
                _ = SendMsgAsync(MSG_HEARTBEAT, new { ping = "ping" });
                _lastHeartbeat = Time.time;
            }
            if (Time.time - _lastPongTime > HeartbeatTimeout)
            {
                Debug.LogWarning("心跳超时，断开重连");
                _ = TryReconnectAsync(serverIp, serverTcpPort);
            }
        }

        foreach (var kv in _remoteStates)
        {
            var id = kv.Key;
            if (!_players.ContainsKey(id)) continue;
            var go = _players[id];
            var target = kv.Value.Target;
            go.transform.position = Vector3.Lerp(go.transform.position, target, 1f - Mathf.Exp(-remoteLerpSpeed * Time.deltaTime));
        }
    }

    void OnDestroy()
    {
        Debug.Log("NetworkManager 正在销毁");
        _isApplicationQuitting = true;
        CloseConnection();

        try { _cts?.Dispose(); _cts = null; } catch (Exception ex) { Debug.LogWarning($"释放 CancellationTokenSource 时出错: {ex.Message}"); }
        try { _udpClient?.Dispose(); } catch { }
    }

    void OnApplicationQuit()
    {
        Debug.Log("应用程序正在退出");
        _isApplicationQuitting = true;
        CloseConnection();
        try { _udpClient?.Dispose(); } catch { }
    }

    void OnApplicationPause(bool pauseStatus)
    {
        if (pauseStatus)
        {
            Debug.Log("应用暂停，关闭网络连接");
            CloseConnection();
        }
    }

    void OnApplicationFocus(bool hasFocus)
    {
        if (!hasFocus) Debug.Log("应用失去焦点");
    }

    [Serializable] public class PlayerJoinBroadcast { public int playerId; }
    [Serializable] public class PlayerLeaveBroadcast { public int playerId; }
    [Serializable] public class LoginResponse { public int playerId; public string result; }
    [Serializable] public class MoveBroadcast { public int playerId; public float x; public float y; public float z; }
    [Serializable] public class HeartbeatMsg { public string ping; }
    [Serializable] private class ServerPubKeyMsg { public string publicKey; }
    [Serializable] public class LoginRequest { public string username; public string password; }
}
