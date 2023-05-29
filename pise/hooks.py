import logging
import maat
from pise import sym_ex_helpers_maat, sym_ex_maat

logger = logging.getLogger(__name__)

ADDR_SIZE = 8


# This interface describes a callsite that sends/receive messages in the binary, and therefore should be hooked
class CallSite:
    # This function should set the hook within the symbolic execution engine
    # In our case it gets the angr project with the executable loaded
    # Return value is ignored
    def set_hook(self, maat_engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        raise NotImplementedError()

    # This function should extract the buffer pointer and the buffer length from the program state
    # It is given the call_context as angr's SimProcedure instance, which contains under call_context.state the program state
    # Should return: (buffer, length) tuple
    def extract_arguments(self, call_context):
        raise NotImplementedError()

    @staticmethod
    def do_ret_from_plt(engine: maat.MaatEngine):
        engine.cpu.rip = engine.mem.read(engine.cpu.rsp.as_uint(), ADDR_SIZE)
        engine.cpu.rsp = engine.cpu.rsp.as_uint() + ADDR_SIZE


class LibcCallSite(CallSite):
    def __init__(self, offset_plt_ent: int):
        self.offset_plt_ent = offset_plt_ent

    def set_hook(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes) -> None:
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.AFTER, filter=sym_ex_maat.BASE_ADDR+self.offset_plt_ent,
                         callbacks=[self.make_callback()])

    def execute_callback(self, engine: maat.MaatEngine) -> maat.ACTION:
        engine.cpu.rax = engine.cpu.rdi
        #logger.debug(engine.mem)
        CallSite.do_ret_from_plt(engine)
        return maat.ACTION.CONTINUE

    def make_callback(self):
        return lambda engine: self.execute_callback(engine)


class HtonsHook(LibcCallSite):
    pass


class InetPtonHook(LibcCallSite):
    pass


class ConnectHook(LibcCallSite):
    pass


class SocketHook(LibcCallSite):
    pass


class NetHook:
    SEND = 0
    RECV = 1

    def __init__(self, callsite_handler: CallSite):
        self.callsite_handler = callsite_handler
        self.type = None

    @staticmethod
    def check_monitoring_complete(pise_attr: sym_ex_helpers_maat.PISEAttributes):
        return len(pise_attr.inputs) == pise_attr.idx

    def execute_net_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        buffer_arg, length_arg = self.callsite_handler.extract_arguments(engine)
        buffer_addr = buffer_arg.as_uint(pise_attr.make_model())
        length = length_arg.as_uint(pise_attr.make_model())

        message_type = pise_attr.inputs[pise_attr.idx]
        #engine.mem.map(buffer_addr, buffer_addr+length, maat.PERM.RW)
        if self.type == NetHook.RECV:
            engine.mem.make_concolic(buffer_addr, length, 1, "msg_%d" % pise_attr.idx)
        for (offset, value) in message_type.predicate.items():
            offset = int(offset)
            value = int(value)
            if offset >= length:
                logger.debug('Bad length')
                return maat.ACTION.HALT
            symb_byte = engine.mem.read(buffer_addr + offset, 1)

            pise_attr.add_constraint(symb_byte == value)
        res = pise_attr.make_model()
        if res is None:
            logger.debug('Unsat')
            return maat.ACTION.HALT
        pise_attr.idx += 1
        LibcCallSite.do_ret_from_plt(engine)
        engine.vars.update_from(res)
        return maat.ACTION.CONTINUE if not NetHook.check_monitoring_complete(pise_attr) else maat.ACTION.HALT


class SendHook(NetHook):
    SEND_STRING = 'SEND'

    def __init__(self, callsite_handler: CallSite, **kwargs):
        super().__init__(callsite_handler)
        self.type = NetHook.SEND

    def execute_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        logger.debug('Send hook')
        if NetHook.check_monitoring_complete(pise_attr) or pise_attr.inputs[pise_attr.idx].type != SendHook.SEND_STRING:
            return maat.ACTION.HALT
        logger.debug('Net hook')
        action = self.execute_net_callback(engine, pise_attr)
        #logger.debug('Checking satisfiability')
        if action == maat.ACTION.HALT or not pise_attr.solver.check():
            return maat.ACTION.HALT
        #logger.debug('Checking satisfiability')
        return maat.ACTION.CONTINUE

    def make_callback(self, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        return lambda engine: self.execute_callback(engine, pise_attr)


class RecvHook(NetHook):
    RECEIVE_STRING = 'RECEIVE'

    def __init__(self, callsite_handler: CallSite, **kwargs):
        super().__init__(callsite_handler)
        self.type = NetHook.RECV

    def execute_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        if NetHook.check_monitoring_complete(pise_attr) or pise_attr.inputs[pise_attr.idx].type != RecvHook.RECEIVE_STRING:
            return maat.ACTION.HALT
        return self.execute_net_callback(engine, pise_attr)

    def make_callback(self, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        return lambda engine: self.execute_callback(engine, pise_attr)


class AsyncHook:
    def resume(self):
        raise NotImplementedError()

    def emulate_recv(self):
        raise NotImplementedError()
