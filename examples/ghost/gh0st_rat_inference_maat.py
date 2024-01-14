import logging

from pise import sym_ex_maat, server, hooks, sym_ex_helpers_maat
import maat

BINARY_PATH = './examples/ghost/gh0st_like'

MAIN_OFFSET = 0x2556
SOCKET_OFFSET = 0x11b4
CONNECT_OFFSET = 0x11a4
SCANF_OFFSET = 0x11e4
RECV_OFFSET = 0x1104
SEND_OFFSET = 0x1144
PRINTF_OFFSET = 0x1150
PUTS_OFFSET = 0x1110
CANARY_CHECK_OFFSET = 0x1120



class Gh0stSendHook(hooks.CallSite):

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        send_hook = hooks.SendHook(self)
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.AFTER, filter=SEND_OFFSET + sym_ex_maat.BASE_ADDR,
                         callbacks=[send_hook.make_callback(pise_attr)])

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


class Gh0stRecvHook(hooks.CallSite):

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        recv_hook = hooks.RecvHook(self)
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.AFTER, filter=RECV_OFFSET + sym_ex_maat.BASE_ADDR,
                         callbacks=[recv_hook.make_callback(pise_attr)])

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_ex_maat.QueryRunner(BINARY_PATH,
                                           [Gh0stRecvHook(),
                                            Gh0stSendHook(),
                                            hooks.ConnectHook(CONNECT_OFFSET),
                                            hooks.SocketHook(SOCKET_OFFSET),
                                            hooks.LibcCallSite(PRINTF_OFFSET),
                                            hooks.LibcCallSite(PUTS_OFFSET),
                                            hooks.LibcCallSite(CANARY_CHECK_OFFSET)
                                            ],
                                           MAIN_OFFSET)
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
