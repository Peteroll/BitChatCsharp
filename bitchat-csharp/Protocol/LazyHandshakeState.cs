namespace Bitchat.Protocol;

public enum LazyHandshakeState
{
    None,
    HandshakeQueued,
    Handshaking,
    Established,
    Failed
}
