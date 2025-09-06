namespace Game.Network
{
    /// <summary>
    /// 网络消息ID枚举
    /// </summary>
    public enum MsgId
    {
        None = 0,
        MoveRequest = 1,      // 玩家移动请求
        MoveBroadcast = 2,    // 广播玩家移动
        LoginRequest = 3,     // 登录请求
        LoginResponse = 4,    // 登录响应
        // 可以继续扩展
    }

    /// <summary>
    /// 网络相关常量
    /// </summary>
    public static class NetConst
    {
        public const int BufferSize = 1024 * 4; // 4KB缓冲区
        public const int Port = 8080;           // 默认端口
        public const string ServerIP = "127.0.0.1"; // 默认服务器IP
    }
}
