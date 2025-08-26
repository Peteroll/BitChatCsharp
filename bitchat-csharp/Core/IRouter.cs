namespace Bitchat.Core;

using Bitchat.Protocol;

public interface IRouter
{
    void Broadcast(string senderPeerHex, string content);
    void PrivateMessage(string senderPeerHex, string targetPeerHex, string content);
    void HandleIncoming(byte[] raw);
}
