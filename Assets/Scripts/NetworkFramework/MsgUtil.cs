using System;
using System.Text;
using Newtonsoft.Json;

[Serializable]
public class NetMessage<T>
{
    public int msgId;
    public T data;
}

public static class MsgUtil
{
    public static byte[] BuildMessageBody<T>(int msgId, T obj)
    {
        var netMsg = new NetMessage<T> { msgId = msgId, data = obj };
        string json = JsonConvert.SerializeObject(netMsg);
        return Encoding.UTF8.GetBytes(json);
    }

    public static byte[] EncodeMessage<T>(int msgId, T obj)
    {
        var body = BuildMessageBody(msgId, obj);
        var lenBytes = BitConverter.GetBytes(body.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
        var packet = new byte[4 + body.Length];
        Array.Copy(lenBytes, 0, packet, 0, 4);
        Array.Copy(body, 0, packet, 4, body.Length);
        return packet;
    }

    public static NetMessage<T> DecodeMessage<T>(byte[] body)
    {
        var json = Encoding.UTF8.GetString(body);
        return JsonConvert.DeserializeObject<NetMessage<T>>(json);
    }

    public static int GetMessageId(byte[] body)
    {
        var json = Encoding.UTF8.GetString(body);
        var temp = JsonConvert.DeserializeObject<NetMessage<object>>(json);
        return temp.msgId;
    }
}