import logging

from pise import sym_execution, server, hooks, hooks_angr
from examples import toy_client_inference_maat


class ToySendHook(hooks_angr.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        # Something messed up with angr return value handling, so we simply set rax with the desired return value
        call_context.state.regs.rax = length

    def set_hook(self, p):
        p.hook_symbol('send', hooks_angr.SendHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.edx
        buffer = call_context.state.regs.rsi
        return buffer, length


class ToyRecvHook(hooks_angr.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        # Something messed up with angr return value handling, so we simply set rax with the desired return value
        call_context.state.regs.rax = length

    def set_hook(self, p):
        p.hook_symbol('recv', hooks_angr.RecvHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.edx
        buffer = call_context.state.regs.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = sym_execution.QueryRunner(toy_client_inference_maat.BINARY_PATH, [ToySendHook(), ToyRecvHook()],
                                             [toy_client_inference_maat.ToySendHook(),
                                              toy_client_inference_maat.ToyRecvHook(),
                                              hooks.SocketHook(0x1214), hooks.InetPtonHook(0x11d4),
                                              hooks.ConnectHook(0x1204)])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
