from socketserver import BaseRequestHandler

SERVER_PORT = 53
SERVER_IP = '0.0.0.0'


class DNSHandler(BaseRequestHandler):
    """
    DNS Protocol:
        Header section:
            16 bits for header
                1 bit for message type (0 - query, 1 - response)
                4 bits for opcode (???)
                1 bit for isAuthoritative (0 - no, 1 - yes; should almost always be 0 for this server)
                1 bit for truncation (0 - no split, 1 - msg was split from size)
                1 bit for recursion desired (0 - query should not be recursive, 1 - query is recursive)
                1 bit for recursion availability (0 - server cannot perform recursion query, 1 - server can)
                1 bit for reserved (0 - ?; should always be 0)
                [Seems that this isn't exact, the next two bits could be 0 or they can be set correctly; some resources
                have these marked as reserved still.]
                1 bit for isAnswerAuthenticated (0 - not, 1 - is; should probably be 0 for this server)
                1 bit for is non-authenticated data accepted (0 - non-authenticated data not accepted, 1 - it is accepted)
                4 bit for reply code (????)
            16 bits for number of questions
            16 bits for number of answers
            16 bits for number of authoritative records
            16 bits for number of additional records
        Query section:
            ?? bits for name (URL is split into labels, for each label, the characters are encoded with ascii value,
                              then the label is succeeded by its length in bytes. Repeat for each label. To finish this
                              section, it is terminated with 0)
                              (https://routley.io/posts/hand-writing-dns-messages/) here for more info.
            16 bits for record type (only expecting A which means value of 0x01)
            16 bits for query class (always expecting IN, so value of 0x01)
        Answer section:
            16 bits for name reference (first two bits are always 1, rest of the 14 bits are unsigned integer,
                                        said integer refers to byte offset from the beginning of the message
                                        to the 1st occurrence of the name.)
            16 bits for record type
            16 bits for query class
            32 bits for time to live
            16 bits for data length(value in bytes)
            ?? bits for address (length is equal to data length)
    """
    def handle(self) -> None:
        received, socket = self.request
        print(f'{self.client_address[0]} sent {received.decode("utf-8")}.')

        socket.sendto(b'hi', self.client_address)