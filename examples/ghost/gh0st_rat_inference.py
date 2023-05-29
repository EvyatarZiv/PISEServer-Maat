import logging

from angr import SimProcedure
from pise import sym_execution, server, hooks_angr, hooks
import gh0st_rat_inference_maat


class Gh0stSendHook(hooks_angr.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        return 0

    def set_hook(self, project):
        project.hook_symbol('send_message', hooks_angr.SendHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.rsi
        buffer = call_context.state.regs.rdi
        return buffer, length


class Gh0stRecvHook(hooks_angr.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        pass

    def set_hook(self, p):
        p.hook_symbol('get_message', hooks_angr.RecvHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.rsi
        buffer = call_context.state.regs.rdi
        return buffer, length


class HasMsgSimProc(SimProcedure):
    def run(self, *args, **kwargs):
        retval = self.state.solver.BVS("retval", 32)
        self.state.add_constraints(self.state.solver.Or(retval == 0, retval == 1))
        self.state.regs.eax = retval


class HasMsgHook(hooks_angr.SendReceiveCallSite):
    def get_return_value(self, buff, length, call_context=None):
        pass

    def set_hook(self, p):
        p.hook_symbol('has_message', HasMsgSimProc())

    def extract_arguments(self, call_context):
        pass


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('examples/ghost/gh0st_like', [Gh0stSendHook(), Gh0stRecvHook(),
                                                                           HasMsgHook()],
                                             [gh0st_rat_inference_maat.Gh0stRecvHook(),
                                              gh0st_rat_inference_maat.Gh0stSendHook(),
                                              hooks.ConnectHook(gh0st_rat_inference_maat.CONNECT_OFFSET)],
                                             gh0st_rat_inference_maat.MAIN_OFFSET)
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
