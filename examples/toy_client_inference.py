import logging

from pise import sym_ex_maat, server, hooks
import maat

START_ADDRESS=0x0
class ToySendHook(hooks.SendReceiveCallSite):

    def set_hook(self, p):
        p.hooks.add(maat.EVENT.EXEC,maat.WHEN.BEFORE,0x1134+START_ADDRESS)

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


class ToyRecvHook(hooks.SendReceiveCallSite):

    def set_hook(self, p):
        p.hooks.add(maat.EVENT.EXEC, maat.WHEN.BEFORE, 0x1174 + START_ADDRESS)

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = sym_ex_maat.QueryRunner('examples/toy_example/toy_example', [ToySendHook(), ToyRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
