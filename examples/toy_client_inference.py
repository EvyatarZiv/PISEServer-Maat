import logging

from pise import sym_execution, server, hooks


class ToySendHook(hooks.SendReceiveCallSite):

    def set_hook(self, p):
        #p.hook_symbol('send', hooks.SendHook(self))
        pass

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


class ToyRecvHook(hooks.SendReceiveCallSite):

    def set_hook(self, p):
        #p.hook_symbol('recv', hooks.RecvHook(self))
        pass

    def extract_arguments(self, call_context):
        length = call_context.cpu.rdx
        buffer = call_context.cpu.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    # logging.getLogger('angr').setLevel(logging.INFO)
    query_runner = sym_execution.QueryRunner('examples/toy_example/toy_example', [ToySendHook(), ToyRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
