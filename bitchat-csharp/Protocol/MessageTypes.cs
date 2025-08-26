using System;

namespace Bitchat.Protocol;

public enum MessageType : byte
{
    Announce = 0x01,
    Leave = 0x03,
    Message = 0x04,
    FragmentStart = 0x05,
    FragmentContinue = 0x06,
    FragmentEnd = 0x07,
    DeliveryAck = 0x0A,
    DeliveryStatusRequest = 0x0B,
    ReadReceipt = 0x0C,
    NoiseHandshakeInit = 0x10,
    NoiseHandshakeResp = 0x11,
    NoiseEncrypted = 0x12,
    NoiseIdentityAnnounce = 0x13,
    VersionHello = 0x20,
    VersionAck = 0x21,
    ProtocolAck = 0x22,
    ProtocolNack = 0x23,
    SystemValidation = 0x24,
    HandshakeRequest = 0x25,
    Favorited = 0x30,
    Unfavorited = 0x31,
}
