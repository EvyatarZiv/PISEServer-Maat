import logging

from pise import sym_ex_maat, server, hooks, sym_ex_helpers_maat
import maat, time

START_ADDRESS = 0x0


class ToySendHook(hooks.CallSite):

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        send_hook = hooks.SendHook(self)
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, filter=0x1174 + START_ADDRESS,
                         callbacks=[send_hook.make_callback(pise_attr)])

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


class ToyRecvHook(hooks.CallSite):

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        recv_hook = hooks.RecvHook(self)
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, filter=0x1134 + START_ADDRESS,
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
    query_runner = sym_ex_maat.QueryRunner('/Users/evyatarziv/Documents/Technion/Spring '
                                           '2023/ISC236349/PISE-MAAT/examples/toy_example',
                                           [ToySendHook(), ToyRecvHook()])
    """, hooks.SocketHook(0x1214),
                                            hooks.HtonsHook(0x1164), hooks.InetPtonHook(0x11d4),
                                            hooks.ConnectHook(0x1204), ToyScanfHook(0x11e4)])"""
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
