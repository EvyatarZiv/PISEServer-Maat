import logging

from pise import sym_ex_maat, server, hooks, sym_ex_helpers_maat
import maat

BINARY_PATH = './examples/toy_example/toy_example'

MAIN_OFFSET = 0x2581
SOCKET_OFFSET = 0x11b0
CONNECT_OFFSET = 0x11a0
RECV_OFFSET = 0x1100
SEND_OFFSET = 0x1140


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
    query_runner = sym_ex_maat.QueryRunner('examples/ghost/gh0st_like_no_switch',
                                           [Gh0stSendHook(), Gh0stRecvHook()], MAIN_OFFSET)
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
