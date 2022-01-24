import Foundation
import NIO

struct AnyError: Error {}

final class SMTPClientOutboundHandler: MessageToByteEncoder {
    public typealias OutboundIn = SMTPClientMessage
    
    init() {}
    
    public func encode(data: SMTPClientMessage, out: inout ByteBuffer) throws {
        switch data {
        case .none:
            return
        case .helo(let hostname):
            out.writeStaticString("HELO ")
            out.writeString(hostname)
        case .ehlo(let hostname):
            out.writeStaticString("EHLO ")
            out.writeString(hostname)
        case .custom(let request):
            out.writeString(request.text)
        case .startMail(let mail):
            out.writeStaticString("MAIL FROM: <")
            out.writeString(mail.from.email)
            out.writeString("> BODY=8BITMIME")
        case .mailRecipient(let address):
            out.writeString("RCPT TO: <\(address)>")
        case .startMailData:
            out.writeStaticString("DATA")
        case .mailData(let mail):
            var mailData = ""
            for header in mail.headers {
                mailData += "\(header.key): \(header.value)\r\n"
            }
            mailData += "Content-Type: \(mail.contentType.rawValue); charset=\"utf-8\"\r\n"
            mailData += "\r\n"
            mailData += mail.text
            mailData += "\r\n." // mail data termination sequence <crlf>.<crlf>, see below for second <crlf>
            out.writeString(mailData)
        case .starttls:
            out.writeStaticString("STARTTLS")
        case .authenticatePlain:
            out.writeStaticString("AUTH PLAIN")
        case .authenticateLogin:
            out.writeStaticString("AUTH LOGIN")
        case .authenticateCramMd5:
            out.writeStaticString("AUTH CRAM-MD5")
        case .authenticateXOAuth2(let credentials):
            out.writeStaticString("AUTH XOAUTH2 ")
            out.writeString(credentials)
        case .authenticateUser(let user):
            out.writeString(user.base64Encoded)
        case .authenticatePassword(let password):
            out.writeString(password.base64Encoded)
        case .quit:
            out.writeStaticString("QUIT")
        }
        
        out.writeInteger(cr)
        out.writeInteger(lf)
    }
}

final class SMTPClientInboundHandler: ByteToMessageDecoder {
    public typealias InboundOut = Never
    let context: SMTPClientContext
    
    init(context: SMTPClientContext) {
        self.context = context
    }
    
    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard let rawSMTPServerMessages = try buffer.rawSMTPServerMessages() else {
            return .needMoreData
        }
        let messages = try rawSMTPServerMessages.map { try SMTPServerMessage(string: $0) }
        guard messages.last?.isClosingMessage == true else {
            return .needMoreData
        }
        
        buffer.moveReaderIndex(to: buffer.writerIndex)
        self.context.receive(messages)
        return .continue
    }
    
    public func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        let decodingState: DecodingState
        if buffer.readableBytes > 0 {
            decodingState = try decode(context: context, buffer: &buffer)
        }
        else {
            decodingState = .continue
        }
        self.context.disconnect()
        return decodingState
    }
}

extension ByteBuffer {
    
    func rawSMTPServerMessages() throws -> [String]? {
        guard endsWithCRLF else { return nil }
        var messages = [String]()
        var messageStartIndex = readerIndex // The position of the first character in a nonempty string.
        var messageEndIndex = readerIndex + 1 // A string’s “past the end” position—that is, the position one greater than the last valid subscript argument.
        while messageEndIndex + 1 < writerIndex {
            
            if getInteger(at: messageEndIndex + 0) == cr &&
               getInteger(at: messageEndIndex + 1) == lf {
                guard let message = getString(at: messageStartIndex, length: messageEndIndex - messageStartIndex) else {
                    throw SMTPError.invalidMessage
                }
                messages.append(message)
                messageStartIndex = messageEndIndex + 2
                messageEndIndex = messageStartIndex + 1
            }
            else {
                messageEndIndex += 1
            }
            
        }
        return messages
    }
    
    var endsWithCRLF: Bool {
        guard readableBytes >= 2 else { return false }
        return getInteger(at: readerIndex + readableBytes - 2) == cr &&
               getInteger(at: readerIndex + readableBytes - 1) == lf
    }
}

extension SMTPServerMessage {
    
    init(string: String) throws {
        guard let code = Int(string.prefix(3)) else { throw SMTPError.invalidMessage }
        self.code = code
        
        guard string.count >= 4 else { throw SMTPError.invalidMessage }
        switch string[string.index(string.startIndex, offsetBy: 3)] {
        case "-":
            isClosingMessage = false
        case " ":
            isClosingMessage = true
        default:
            throw SMTPError.invalidMessage
        }
        
        message = String(string.suffix(from: string.index(string.startIndex, offsetBy: 4)))
    }
}
