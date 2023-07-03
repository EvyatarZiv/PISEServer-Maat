import logging
import maat
from pise import sym_ex_helpers_maat, sym_ex_maat, entities

logger = logging.getLogger(__name__)

ADDR_SIZE = 8
NUM_SOL = 10


def extract_name(predicate: dict) -> str:
    if len(predicate) == 0:
        return 'ANY'
    name = ''
    for i in sorted(predicate, key=int):
        if chr(predicate[i]).isprintable():
            name += chr(predicate[i])

    if name == '':
        return 'UNKNOWN'

    return name


def match_byte(probing_results, i):
    ref = probing_results[0][i]
    return all(map(lambda m: m[i] == ref, probing_results))


def extract_predicate(results):
    predicate = dict()
    for i in range(len(results[0])):
        if match_byte(results, i):
            predicate[str(i)] = results[0][i]
    return predicate


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
        engine.hooks.add(maat.EVENT.EXEC, maat.WHEN.AFTER, filter=sym_ex_maat.BASE_ADDR + self.offset_plt_ent,
                         callbacks=[self.make_callback(pise_attr)])

    def execute_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes = None) -> maat.ACTION:
        engine.cpu.rax = engine.cpu.rdi
        # logger.debug(engine.mem)
        CallSite.do_ret_from_plt(engine)
        return maat.ACTION.CONTINUE

    def make_callback(self, pise_attr: sym_ex_helpers_maat.PISEAttributes = None):
        return lambda engine: self.execute_callback(engine, pise_attr)


class HtonsHook(LibcCallSite):
    pass


class InetPtonHook(LibcCallSite):
    pass


class ConnectHook(LibcCallSite):
    pass


class SocketHook(LibcCallSite):
    pass

class StrcmpHook(LibcCallSite):
    def execute_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes = None) -> maat.ACTION:
        # logger.debug(engine.mem)
        s1_ptr = engine.cpu.rdi
        s2_ptr = engine.cpu.rsi
        if engine.mem.read(s1_ptr.as_uint(),1).is_concolic(engine.vars):
            CallSite.do_ret_from_plt(engine)
            pise_attr.save_engine_state(engine)
            pise_attr.add_constraint(engine.cpu.rax == 0)
            idx = 0
            while True:
                ch = engine.mem.read(s2_ptr.as_uint(engine.vars)+idx, 1)
                cond = engine.mem.read(s1_ptr.as_uint(engine.vars)+idx, 1) == ch
                print(cond, ch, engine.mem.read(s1_ptr.as_uint(engine.vars)+idx, 1))
                pise_attr.add_constraint(cond)
                if ch.as_uint(engine.vars) == 0x0 or not pise_attr.gen_solver().check():
                    break
                idx += 1
            if not pise_attr.gen_solver().check():
                print("UNSAT STRCMP")
                print(pise_attr.gen_conditions())
                print(engine.vars)
                pise_attr.pop_engine_state(engine)
        return maat.ACTION.CONTINUE

    def make_callback(self, pise_attr: sym_ex_helpers_maat.PISEAttributes = None):
        return lambda engine: self.execute_callback(engine, pise_attr)

class NetHook:
    SEND = 0
    RECV = 1

    def __init__(self, callsite_handler: CallSite):
        self.callsite_handler = callsite_handler
        self.type = None

    def gen_probing_results(self, engine: maat.MaatEngine, buffer_addr, length, pise_attr: sym_ex_helpers_maat.PISEAttributes) -> dict:
        results = dict()
        for j in range(length):
            next_byte = engine.mem.read(buffer_addr + j, 1).as_uint(engine.vars)
            solver = pise_attr.gen_solver()
            solver.add(engine.mem.read(buffer_addr + j, 1) != next_byte)
            if not solver.check():
                results[str(j)] = next_byte #.to_bytes(length=1, byteorder='big')
        return results

    @staticmethod
    def check_monitoring_complete(pise_attr: sym_ex_helpers_maat.PISEAttributes):
        return len(pise_attr.inputs) == pise_attr.idx

    def probe_recv_at_next_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        print('Adding RECV symbol')
        predicate = self.gen_probing_results(engine, pise_attr.pending_buffer_addr, pise_attr.pending_buffer_length, pise_attr)
        sym = entities.MessageTypeSymbol(RecvHook.RECEIVE_STRING, extract_name(predicate), predicate)
        pise_attr.new_syms.append(sym)
        print(sym.__dict__)

    def execute_net_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        buffer_arg, length_arg = self.callsite_handler.extract_arguments(engine)
        buffer_addr = buffer_arg.as_uint(pise_attr.make_model())
        length = length_arg.as_uint(pise_attr.make_model())

        message_type = pise_attr.inputs[pise_attr.idx]
        # engine.mem.map(buffer_addr, buffer_addr+length, maat.PERM.RW)
        if self.type == NetHook.RECV:
            engine.mem.make_concolic(buffer_addr, length, 1, "msg_%d" % pise_attr.idx)
        for (offset, value) in message_type.predicate.items():
            offset = int(offset)
            value = int(value)
            if offset >= length:
                return maat.ACTION.HALT
            symb_byte = engine.mem.read(buffer_addr + offset, 1)

            pise_attr.add_constraint(symb_byte == value)
        res = pise_attr.make_model()
        if res is None:
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
        if pise_attr.probing:
            if not pise_attr.pending_probe:
                print('Adding SEND symbol')
                buffer_arg, length_arg = self.callsite_handler.extract_arguments(engine)
                buffer_addr = buffer_arg.as_uint(pise_attr.make_model())
                length = length_arg.as_uint(pise_attr.make_model())
                predicate = self.gen_probing_results(engine, buffer_addr, length, pise_attr)
                sym = entities.MessageTypeSymbol(SendHook.SEND_STRING, extract_name(predicate), predicate)
                pise_attr.new_syms.append(sym)
                print(sym.__dict__)
                return maat.ACTION.HALT
            print('Recv next callback @ send')
            self.probe_recv_at_next_callback(engine, pise_attr)
            return maat.ACTION.HALT
        if pise_attr.inputs[pise_attr.idx].type != SendHook.SEND_STRING:
            return maat.ACTION.HALT
        action = self.execute_net_callback(engine, pise_attr)
        # logger.debug('Checking satisfiability')
        if action == maat.ACTION.HALT or not pise_attr.solver.check():
            return maat.ACTION.HALT
        if NetHook.check_monitoring_complete(pise_attr):
            #pise_attr.probing = NetHook.check_monitoring_complete(pise_attr)
            # LibcCallSite.do_ret_from_plt(engine)
            return maat.ACTION.HALT
        # logger.debug('Checking satisfiability')
        return maat.ACTION.CONTINUE

    def make_callback(self, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        return lambda engine: self.execute_callback(engine, pise_attr)


class RecvHook(NetHook):
    RECEIVE_STRING = 'RECEIVE'

    def __init__(self, callsite_handler: CallSite, **kwargs):
        super().__init__(callsite_handler)
        self.type = NetHook.RECV

    def execute_callback(self, engine: maat.MaatEngine, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        print('Recv hook')
        if pise_attr.probing:
            if not pise_attr.pending_probe:
                pise_attr.pending_probe = True
                buffer_arg, length_arg = self.callsite_handler.extract_arguments(engine)
                pise_attr.pending_buffer_addr = buffer_arg.as_uint(pise_attr.make_model())
                pise_attr.pending_buffer_length = length_arg.as_uint(pise_attr.make_model())
                engine.mem.make_symbolic(pise_attr.pending_buffer_addr, pise_attr.pending_buffer_length, 1, "msg_%d" % pise_attr.idx)
                LibcCallSite.do_ret_from_plt(engine)
                return maat.ACTION.CONTINUE
            print('Recv next callback @ recv')
            self.probe_recv_at_next_callback(engine, pise_attr)
            return maat.ACTION.HALT
        if NetHook.check_monitoring_complete(pise_attr) or pise_attr.inputs[
            pise_attr.idx].type != RecvHook.RECEIVE_STRING:
            #pise_attr.probing = NetHook.check_monitoring_complete(pise_attr)
            #LibcCallSite.do_ret_from_plt(engine)
            return maat.ACTION.HALT
        return self.execute_net_callback(engine, pise_attr)

    def make_callback(self, pise_attr: sym_ex_helpers_maat.PISEAttributes):
        return lambda engine: self.execute_callback(engine, pise_attr)


class AsyncHook:
    def resume(self):
        raise NotImplementedError()

    def emulate_recv(self):
        raise NotImplementedError()
