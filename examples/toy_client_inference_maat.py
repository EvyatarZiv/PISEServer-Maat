import logging

from pise import sym_ex_maat, server, hooks, sym_ex_helpers_maat
import maat, time

START_ADDRESS = 0x0
BINARY_PATH = './examples/toy_example'

MAIN_OFFSET = 0x1309
SOCKET_OFFSET = 0x1214
CONNECT_OFFSET = 0x1204
SCANF_OFFSET = 0x11e4
RECV_OFFSET = 0x1134
SEND_OFFSET = 0x1174


class ToySendHook(hooks.CallSite):

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        send_hook = hooks.SendHook(self)
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, filter=SEND_OFFSET+sym_ex_maat.BASE_ADDR,
                         callbacks=[send_hook.make_callback(pise_attr)])

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


class ToyRecvHook(hooks.CallSite):

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        recv_hook = hooks.RecvHook(self)
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, filter=RECV_OFFSET+sym_ex_maat.BASE_ADDR,
                         callbacks=[recv_hook.make_callback(pise_attr)])

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


SIZE_OF_INT = 4


class ToyScanfHook(hooks.LibcCallSite):
    def execute_callback(self, engine: maat.MaatEngine) -> maat.ACTION:
        var_addr = engine.cpu.rsi.as_uint()
        engine.mem.make_concolic(var_addr, 1, SIZE_OF_INT, str(time.time()))
        hooks.CallSite.do_ret_from_plt(engine)
        return maat.ACTION.CONTINUE


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = sym_ex_maat.QueryRunner(BINARY_PATH,
                                           [ToySendHook(),
                                            ToyRecvHook(),
                                            hooks.SocketHook(SOCKET_OFFSET),
                                            hooks.ConnectHook(CONNECT_OFFSET)], MAIN_OFFSET)
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
